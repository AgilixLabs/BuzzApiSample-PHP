<?php

declare(strict_types=1);

namespace Agilix\BuzzApi;

/**
 * Makes requests to a Buzz API server, authenticating with OAuth 2.0 JWT client
 * credentials (RFC 6749 + RFC 7523).  The client obtains and refreshes Bearer
 * access tokens automatically, retries transient failures with exponential
 * backoff, and backs off when the server signals throttling or backend pressure.
 *
 * Requires PHP 7.4+ with the bundled openssl, curl, and json extensions (and dom,
 * which is only needed if the server answers with XML instead of JSON).
 */
final class BuzzApiClient
{
    /** @var int */
    private const RETRIES_TO_MAKE = 5;
    /** @var float seconds */
    private const INITIAL_WAIT_SECONDS = 1.0;
    /** @var float seconds */
    private const MAX_RETRY_WAIT_SECONDS = 64.0;

    /**
     * The longest server-directed wait (Retry-After / X-RateLimit-Reset) the
     * client will sit out before retrying.  Rate-limit windows are five minutes
     * and the server adds jitter, so a Retry-After of several minutes is normal.
     * Retrying before the server says to only burns quota, so a longer wait
     * fails the request instead of retrying early.
     * @var float seconds
     */
    private const MAX_SERVER_DIRECTED_WAIT_SECONDS = 600.0;

    /**
     * Response codes the server uses in the XML/JSON envelope to say "slow down
     * and retry later" (compared case-insensitively).  Throttles are usually
     * reported with HTTP 200 (the server wraps them for legacy clients), so the
     * envelope code must be checked even when the HTTP status is a success.
     * "TooManyRequests" is what every throttle collapses to when the server is
     * set to report throttles generically; "Service Unavailable" is the code
     * written when the server sheds load before a request is authenticated.
     */
    private const THROTTLE_CODES = [
        'TooManyRequests', 'RetryLater', 'LimitExceeded', 'RateLimit', 'TimeLimit',
        'ServerOverwhelmed', 'BackendPressure', 'Service Unavailable', 'ServiceUnavailable',
    ];

    /** Throttle codes that stand for HTTP 503 rather than 429. */
    private const THROTTLE_CODES_503 = [
        'ServerOverwhelmed', 'BackendPressure', 'Service Unavailable', 'ServiceUnavailable',
    ];

    /**
     * How far before token expiry to proactively refresh.  Tokens are valid for
     * one hour; refreshing five minutes early gives a comfortable window for slow
     * networks or clock skew.
     * @var int seconds
     */
    private const TOKEN_REFRESH_MARGIN_SECONDS = 300;

    /** Fields that must never be written to logs. */
    private const SENSITIVE_FIELDS = [
        'token', 'access_token', 'refresh_token', 'password', 'client_assertion', 'client_secret',
    ];

    /**
     * HTTP status codes that must NOT be retried.  Everything else — network
     * errors, timeouts, 500, 502, 504, 429, 503 — is retried.
     */
    private const NO_RETRY_STATUS = [
        400, 401, 402, 403, 404, 405, 406, 407, 409, 410, 411, 412, 413, 414, 415, 416,
        417, 421, 422, 424, 426, 428, 431, 451,
        501, 505, 506, 508, 510, 511,
    ];

    /** @var string */
    private $serverUrl;
    /** @var string */
    private $userAgent;
    /** @var bool */
    private $verbose;
    /** @var int milliseconds */
    private $timeoutMs;
    /** @var callable|null function(string $level, string $message): void */
    private $logger;

    /** @var string|null */
    private $token = null;
    /** @var string */
    private $oauthUserId;
    /** @var string */
    private $oauthKid;
    /** @var \OpenSSLAsymmetricKey|resource */
    private $privateKey;
    /** @var string */
    private $tokenEndpoint;
    /** @var float epoch seconds */
    private $tokenExpiry = 0.0;

    /**
     * Epoch seconds before which no request from this client should be sent.
     * Set whenever the server signals throttling or backend pressure, so later
     * requests on this client wait out the window instead of each discovering
     * the throttle separately.  PHP runs a client on one thread, so a plain
     * property is enough; separate processes each keep their own window.
     * @var float
     */
    private $throttledUntil = 0.0;

    /**
     * @param string $serverUrl   Buzz server URL, including protocol, without a trailing '/'.
     * @param string $userAgent   User-Agent header value sent on every request.
     * @param string $oauthUserId userid of the Application Identity account (OAuth client_id / JWT iss+sub).
     * @param string $oauthKid    Key id (kid) chosen when the public key was registered.
     * @param \OpenSSLAsymmetricKey|resource $privateKey RSA private key (see fromPemFile()).
     * @param array  $options      verbose(bool), timeout(int seconds), logger(callable).
     */
    public function __construct(
        string $serverUrl,
        string $userAgent,
        string $oauthUserId,
        string $oauthKid,
        $privateKey,
        array $options = []
    ) {
        if ($oauthUserId === '') {
            throw new \InvalidArgumentException('oauthUserId is required');
        }
        if ($oauthKid === '') {
            throw new \InvalidArgumentException('oauthKid is required');
        }
        if ($privateKey === null || $privateKey === false) {
            throw new \InvalidArgumentException('privateKey is required');
        }

        $this->serverUrl = rtrim(trim($serverUrl), '/');
        $this->userAgent = $userAgent;
        $this->oauthUserId = $oauthUserId;
        $this->oauthKid = $oauthKid;
        $this->privateKey = $privateKey;
        $this->verbose = (bool) ($options['verbose'] ?? false);
        $this->timeoutMs = (int) (($options['timeout'] ?? 600) * 1000);
        $this->logger = $options['logger'] ?? null;
        $this->tokenEndpoint = $this->serverUrl . '/api/oauth/token';
    }

    /**
     * Create a client, loading the RSA private key from a PEM file.
     *
     * @param array $options see the constructor.
     */
    public static function fromPemFile(
        string $serverUrl,
        string $userAgent,
        string $oauthUserId,
        string $oauthKid,
        string $privateKeyPath,
        array $options = []
    ): self {
        $pem = @file_get_contents($privateKeyPath);
        if ($pem === false) {
            throw new \RuntimeException("Could not read private key file: {$privateKeyPath}");
        }
        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            throw new \RuntimeException("Could not parse RSA private key from: {$privateKeyPath}");
        }
        return new self($serverUrl, $userAgent, $oauthUserId, $oauthKid, $key, $options);
    }

    /** The current Bearer token, if one has been obtained. */
    public function getToken(): ?string
    {
        return $this->token;
    }

    /**
     * Make a request to a Buzz command that returns JSON.
     *
     * @param string      $method       HTTP method, e.g. 'GET' or 'POST'.
     * @param string|null $cmd          Command to call, e.g. 'getuser2'.
     * @param array       $params       Query-string parameters.
     * @param mixed       $jsonBody     Value serialized as the JSON request body.
     * @param bool        $includeToken Attach the OAuth Bearer token.
     * @return array|null The decoded JSON response (an XML response is converted
     *                    to the same shape), or null if the body was empty.
     * @throws BuzzApiThrottledException if the request is still throttled after retrying.
     * @throws BuzzApiException for other failures, including a success body that cannot be parsed.
     */
    public function jsonRequest(
        string $method,
        ?string $cmd = null,
        array $params = [],
        $jsonBody = null,
        bool $includeToken = true
    ): ?array {
        if ($includeToken) {
            $this->ensureToken();
        }

        $content = $jsonBody === null ? null : json_encode($jsonBody);

        try {
            $node = $this->requestWithRetry($method, $cmd, $params, $content, $includeToken);
            $this->traceResponse($node);
            $authenticationRejected = self::responseCode($node) === 'NoAuthentication';
        } catch (BuzzApiException $e) {
            // REST-style endpoints report an expired or revoked token as HTTP 401, possibly with no envelope.
            if (!($includeToken && $this->token !== null && $e->getStatusCode() === 401)) {
                throw $e;
            }
            $node = null;
            $authenticationRejected = true;
        }

        // If the token expired or was revoked, re-authenticate and retry once.
        if ($includeToken && $this->token !== null && $authenticationRejected) {
            $this->log('debug', 'Re-authenticating because the request was rejected as unauthenticated (NoAuthentication or HTTP 401)');
            $this->authenticateOAuth();
            $node = $this->requestWithRetry($method, $cmd, $params, $content, $includeToken);
            $this->traceResponse($node);
        }

        return $node;
    }

    /**
     * Verify that a Buzz JSON response indicates success.
     *
     * @param array|null $responseJson         The decoded response to check.
     * @param bool       $checkChildResponses  Also verify nested child responses (multi-object commands such as CreateUsers2).
     * @return array The verified response node.
     * @throws BuzzApiThrottledException if the response, or any of its child responses, was throttled.
     *         For child responses, getThrottledItemIndexes() lists the items to resubmit.
     * @throws BuzzApiException if the response code is not 'OK'.
     */
    public function verifyResponse(?array $responseJson, bool $checkChildResponses = true): array
    {
        if ($responseJson === null) {
            $this->log('error', 'Buzz API call failed. Expected response.code to be OK, found: null');
            throw new BuzzApiException('Buzz API call failed. Expected response.code to be OK, found: null');
        }

        $toVerify = $responseJson;
        if (isset($responseJson['response']) && is_array($responseJson['response'])) {
            $toVerify = $responseJson['response'];
        }

        $code = self::stringOrNull($toVerify['code'] ?? null);
        if ($code !== 'OK') {
            $redacted = json_encode(self::cloneAndRedact($responseJson));
            $this->log('error', "Buzz API call failed. Expected response.code to be OK, found: {$redacted}");
            if (self::isThrottleCode($code)) {
                throw new BuzzApiThrottledException(
                    "Buzz API call was throttled ({$code}): {$redacted}",
                    $code, $responseJson, [], null, self::throttleStatusCode(200, $code)
                );
            }
            throw new BuzzApiException("Buzz API call failed. Expected response.code to be OK, found: {$redacted}");
        }

        if ($checkChildResponses) {
            $children = self::childResponses($toVerify);

            // Batch and multi-object commands report per-item throttles under an
            // outer OK.  Report them together so the caller can resubmit just
            // those items.  Throttled batch items were rejected without running;
            // a multi-object row that hit BackendPressure (e.g. a database
            // timeout) may have partially run.
            $throttledIndexes = [];
            foreach ($children as $i => $child) {
                if (self::isThrottleCode(self::itemCode($child))) {
                    $throttledIndexes[] = $i;
                }
            }
            if ($throttledIndexes) {
                $firstCode = self::itemCode($children[$throttledIndexes[0]]);
                $indexes = implode(',', $throttledIndexes);
                $this->log('warning', sprintf(
                    '%d of %d items were throttled (%s); resubmit items %s',
                    count($throttledIndexes), count($children), $firstCode, $indexes
                ));
                throw new BuzzApiThrottledException(
                    sprintf(
                        '%d of %d items were throttled (%s). Resubmit the items at indexes %s.',
                        count($throttledIndexes), count($children), $firstCode, $indexes
                    ),
                    $firstCode, $responseJson, $throttledIndexes, null, self::throttleStatusCode(200, $firstCode)
                );
            }

            foreach ($children as $child) {
                $this->verifyResponse(is_array($child) ? $child : null);
            }
        }

        return $toVerify;
    }

    // ── OAuth ────────────────────────────────────────────────────────────────
    private function ensureToken(): void
    {
        if ($this->token !== null
            && microtime(true) < $this->tokenExpiry - self::TOKEN_REFRESH_MARGIN_SECONDS) {
            return;
        }
        $this->authenticateOAuth();
    }

    /**
     * Request a new Bearer access token using a signed JWT client assertion.
     */
    private function authenticateOAuth(): void
    {
        $this->log('info', 'Requesting OAuth access token');

        $retriesRemaining = self::RETRIES_TO_MAKE;
        $baseWait = self::INITIAL_WAIT_SECONDS;
        while (true) {
            // Wait out any throttle window first, then build a fresh assertion on every
            // attempt: JWTs expire in two minutes and a throttle wait can be up to ten, so
            // an assertion built before the wait (or reused) could be past its exp claim.
            $this->waitForThrottleWindow();
            $assertion = $this->buildClientAssertion();
            $form = http_build_query([
                'grant_type' => 'client_credentials',
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion' => $assertion,
            ]);

            [$status, $body, $headers, $errno] = $this->curl(
                'POST',
                $this->tokenEndpoint,
                $form,
                ['Content-Type: application/x-www-form-urlencoded']
            );

            if ($errno !== 0) {
                if ($retriesRemaining > 0) {
                    $wait = self::waitFromRetryHeader($headers, $baseWait);
                    $this->log('debug', "OAuth token request retrying after network error ({$errno})");
                    self::sleepSeconds($wait);
                    $retriesRemaining--;
                    $baseWait *= 2;
                    continue;
                }
                throw new BuzzApiException("OAuth token request failed (network error {$errno}).");
            }

            if ($status < 200 || $status >= 300) {
                // The token endpoint answers with RFC 6749 errors rather than the
                // Buzz envelope: rate limits and backend pressure are 429/503 with
                // error "temporarily_unavailable" and Retry-After.
                $errorJson = $this->tryParseEnvelope($body, $headers['content-type'] ?? null);
                $oauthError = self::stringOrNull($errorJson['error'] ?? null);
                if ($status === 429 || $status === 503 || $oauthError === 'temporarily_unavailable') {
                    $serverWait = self::serverDirectedWait($headers);
                    $wait = self::throttleWait($serverWait, $baseWait);
                    if ($retriesRemaining > 0 && $wait <= self::MAX_SERVER_DIRECTED_WAIT_SECONDS) {
                        $this->log('warning', sprintf(
                            'OAuth token request throttled (%d, %s), backing off %dms, %d retries remaining',
                            $status, $oauthError ?? 'no error code', (int) ($wait * 1000), $retriesRemaining
                        ));
                        $this->extendThrottleWindow($wait);
                        $retriesRemaining--;
                        $baseWait *= 2;
                        continue;   // the throttle window is waited out at the top of the loop
                    }
                    $this->extendThrottleWindow(min($wait, self::MAX_SERVER_DIRECTED_WAIT_SECONDS));
                    throw new BuzzApiThrottledException(
                        "OAuth token request was throttled (HTTP {$status}): {$body}",
                        $oauthError, null, [], $serverWait, self::throttleStatusCode($status, null)
                    );
                }

                if ($retriesRemaining > 0 && self::statusAllowsRetry($status)) {
                    $wait = self::waitFromRetryHeader($headers, $baseWait);
                    $this->log('debug', "OAuth token request retrying after HTTP {$status}");
                    self::sleepSeconds($wait);
                    $retriesRemaining--;
                    $baseWait *= 2;
                    continue;
                }
                $this->log('error', "OAuth token request failed: {$status} {$body}");
                throw new BuzzApiException("OAuth token request failed (HTTP {$status}): {$body}", $status);
            }

            $tokenJson = $this->parseJson($body);
            $accessToken = $tokenJson['access_token'] ?? null;
            if (!is_string($accessToken) || $accessToken === '') {
                throw new BuzzApiException('OAuth token response did not contain an access_token.');
            }
            $expiresIn = (int) ($tokenJson['expires_in'] ?? 3600);
            if ($expiresIn <= 0) {
                $expiresIn = 3600;
            }
            $this->token = $accessToken;
            $this->tokenExpiry = microtime(true) + $expiresIn;
            $this->log('info', "OAuth token obtained, expires in {$expiresIn}s");
            return;
        }
    }

    /**
     * Build a signed JWT client assertion for the token endpoint (RFC 7523 §3),
     * signed with RS256 (RSASSA-PKCS1-v1_5 + SHA-256).
     */
    private function buildClientAssertion(): string
    {
        $now = time();
        $header = ['alg' => 'RS256', 'kid' => $this->oauthKid, 'typ' => 'JWT'];
        $payload = [
            'iss' => $this->oauthUserId,          // issuer = client
            'sub' => $this->oauthUserId,          // subject = client (must equal iss per RFC 7523)
            'aud' => $this->tokenEndpoint,        // audience = token endpoint URL
            'iat' => $now,                        // issued at
            'exp' => $now + 120,                  // expires (2-minute lifetime; max allowed is 5 min)
            'jti' => bin2hex(random_bytes(16)),   // unique id — prevents replay attacks
        ];

        $signingInput = self::base64UrlEncode(json_encode($header))
            . '.' . self::base64UrlEncode(json_encode($payload));

        $signature = '';
        if (!openssl_sign($signingInput, $signature, $this->privateKey, OPENSSL_ALGO_SHA256)) {
            throw new BuzzApiException('Failed to sign the OAuth client assertion.');
        }

        return $signingInput . '.' . self::base64UrlEncode($signature);
    }

    // ── HTTP with retry ────────────────────────────────────────────────────────
    /**
     * Send a request, retrying transient failures, and return the parsed
     * response envelope (XML or JSON, normalised to the decoded-JSON shape).
     * Throttling is recognised from the HTTP status (429/503) or from the
     * envelope code, since the server usually reports throttles as HTTP 200
     * with a code like "TimeLimit" or "BackendPressure" in the body.
     *
     * @return array|null The response envelope, or null for an empty body.
     */
    private function requestWithRetry(
        string $method,
        ?string $cmd,
        array $params,
        ?string $content,
        bool $includeToken
    ): ?array {
        $url = $this->serverUrl . '/cmd' . ($cmd !== null ? '/' . $cmd : '');
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $headers = ['Accept: application/json'];
        if ($content !== null) {
            $headers[] = 'Content-Type: application/json';
        }
        // OAuth always authenticates via the Authorization: Bearer header.
        if ($includeToken && $this->token !== null) {
            $headers[] = 'Authorization: Bearer ' . $this->token;
        }

        $retriesRemaining = self::RETRIES_TO_MAKE;
        $baseWait = self::INITIAL_WAIT_SECONDS;
        while (true) {
            $this->waitForThrottleWindow();

            $this->traceRequest($url);
            [$status, $body, $respHeaders, $errno] = $this->curl($method, $url, $content, $headers);

            if ($errno !== 0) {
                if ($retriesRemaining > 0) {
                    $wait = self::waitFromRetryHeader($respHeaders, $baseWait);
                    $this->log('debug', "Retryable network error invoking {$cmd}: curl errno {$errno}");
                    self::sleepSeconds($wait);
                    $retriesRemaining--;
                    $baseWait *= 2;
                    continue;
                }
                throw new BuzzApiException("Request to {$url} failed (network error {$errno}).");
            }

            // Parse strictly on success: a garbled success body is an error, and
            // it is not retried because the server already ran the command
            // (resending a mutation or a batch could repeat it).  On an error
            // status the envelope is optional (e.g. an HTML page from a proxy).
            $success = $status >= 200 && $status < 300;
            $contentType = $respHeaders['content-type'] ?? null;
            $envelope = $success
                ? $this->parseEnvelope($body, $contentType)
                : $this->tryParseEnvelope($body, $contentType);
            $code = self::responseCode($envelope);

            // API time/rate limiting and backend pressure: HTTP 429/503
            // (REST-style), or an envelope throttle code (usually with HTTP 200).
            // Retry-After is sent either way; X-RateLimit-Reset (seconds until
            // the window resets) is the fallback.
            if ($status === 429 || $status === 503 || self::isThrottleCode($code)) {
                $serverWait = self::serverDirectedWait($respHeaders);
                $wait = self::throttleWait($serverWait, $baseWait);
                $message = self::stringOrNull($envelope['response']['message'] ?? null);
                $detail = sprintf('HTTP %d, code %s%s', $status, $code ?? 'none', $message !== null ? ": {$message}" : '');
                if ($retriesRemaining > 0 && $wait <= self::MAX_SERVER_DIRECTED_WAIT_SECONDS) {
                    $pressure = trim(($respHeaders['x-backend-pressure-service'] ?? '')
                        . ' ' . ($respHeaders['x-backend-pressure-level'] ?? ''));
                    $this->log('warning', sprintf(
                        'Request throttled (%s%s), backing off %dms, %d retries remaining',
                        $detail,
                        $pressure !== '' ? ", backend pressure: {$pressure}" : '',
                        (int) ($wait * 1000), $retriesRemaining
                    ));
                    $this->extendThrottleWindow($wait);
                    $retriesRemaining--;
                    $baseWait *= 2;
                    continue;   // the throttle window is waited out at the top of the loop
                }
                $this->extendThrottleWindow(min($wait, self::MAX_SERVER_DIRECTED_WAIT_SECONDS));
                $reason = $retriesRemaining > 0
                    ? sprintf('server asked to wait %ds, longer than the %ds limit',
                        (int) $wait, (int) self::MAX_SERVER_DIRECTED_WAIT_SECONDS)
                    : 'no retries remaining';
                throw new BuzzApiThrottledException(
                    "Buzz API request was throttled ({$detail}; {$reason})",
                    $code, $envelope, [], $serverWait, self::throttleStatusCode($status, $code)
                );
            }

            if ($success) {
                $this->extendThrottleWindowForThrottledItems($envelope, $respHeaders);
                return $envelope;
            }

            // A REST-style error status with an envelope (e.g. 400 BadRequest,
            // 404 ResourceNotFound): return it so the caller sees the server's
            // code and message, just as it would for the same error wrapped in
            // HTTP 200.  401 is thrown instead so jsonRequest re-authenticates
            // whether or not an envelope came with it.
            if ($code !== null && !self::statusAllowsRetry($status) && $status !== 401) {
                return $envelope;
            }

            if ($retriesRemaining > 0 && self::statusAllowsRetry($status)) {
                $wait = self::waitFromRetryHeader($respHeaders, $baseWait);
                $this->log('debug', "Retrying {$cmd} after HTTP {$status}");
                self::sleepSeconds($wait);
                $retriesRemaining--;
                $baseWait *= 2;
                continue;
            }
            throw new BuzzApiException(
                "Request to " . ($cmd ?? $url) . " failed: HTTP {$status}" . ($code !== null ? " (code {$code})" : ''),
                $status
            );
        }
    }

    /**
     * Perform a single HTTP request with curl.
     *
     * @param string[] $headers
     * @return array{0:int,1:string,2:array<string,string>,3:int} [status, body, lowercasedHeaders, curlErrno]
     */
    private function curl(string $method, string $url, ?string $body, array $headers): array
    {
        $ch = curl_init();
        $respHeaders = [];
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT_MS => $this->timeoutMs,
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_HEADERFUNCTION => function ($ch, $header) use (&$respHeaders) {
                $len = strlen($header);
                // A new status line (after a redirect or "100 Continue") starts a
                // new header block; keep only the final response's headers.
                if (strncmp($header, 'HTTP/', 5) === 0) {
                    $respHeaders = [];
                    return $len;
                }
                $parts = explode(':', $header, 2);
                if (count($parts) === 2) {
                    $respHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return $len;
            },
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $result = curl_exec($ch);
        $errno = curl_errno($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return [$status, is_string($result) ? $result : '', $respHeaders, $errno];
    }

    // ── Logging ────────────────────────────────────────────────────────────────
    private function traceRequest(string $url): void
    {
        // Bodies are never logged: request bodies may contain credentials.
        $level = $this->verbose ? 'info' : 'debug';
        $this->log($level, 'Request: ' . self::redactQueryParam($url, '_token'));
    }

    private function traceResponse(?array $node): void
    {
        if ($node === null) {
            $this->log('debug', 'Response was empty or not JSON');
            return;
        }
        $text = json_encode(self::cloneAndRedact($node));
        $this->log('debug', 'Response: ' . substr($text, 0, 1000));
    }

    private function log(string $level, string $message): void
    {
        if ($this->logger !== null) {
            ($this->logger)($level, $message);
            return;
        }
        // Default logger: DEBUG only when verbose; everything else to STDERR.
        if ($level === 'debug' && !$this->verbose) {
            return;
        }
        fwrite(STDERR, strtoupper($level) . ': ' . $message . "\n");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────
    private function parseJson(string $body): ?array
    {
        if ($body === '') {
            return null;
        }
        $decoded = json_decode($body, true);
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Parse a response body as the XML or JSON envelope.  The server returns XML
     * unless JSON is requested, and some error paths may ignore the Accept
     * header, so XML is converted to the equivalent decoded-JSON shape:
     * attributes and child elements become keys, repeated elements become
     * lists, and text content becomes '$value'.
     *
     * @return array|null The envelope, or null for an empty body.
     * @throws BuzzApiException if the body is not valid XML or JSON.
     */
    private function parseEnvelope(string $body, ?string $contentType): ?array
    {
        if (trim($body) === '') {
            return null;
        }
        $isXml = ($contentType !== null && stripos($contentType, 'xml') !== false)
            || ltrim($body)[0] === '<';
        if (!$isXml) {
            $decoded = json_decode($body, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new BuzzApiException('Could not parse the JSON response: ' . json_last_error_msg());
            }
            if (!is_array($decoded)) {
                throw new BuzzApiException('Could not parse the JSON response: expected an object.');
            }
            return $decoded;
        }

        if (!class_exists(\DOMDocument::class)) {
            throw new BuzzApiException('The server returned XML, but the PHP dom extension is not available to parse it.');
        }
        $previous = libxml_use_internal_errors(true);
        try {
            $doc = new \DOMDocument();
            // No LIBXML_NOENT / LIBXML_DTDLOAD: entities are not expanded and no external DTDs are fetched.
            $loaded = $doc->loadXML($body, LIBXML_NONET);
            $error = libxml_get_last_error();
            libxml_clear_errors();
        } finally {
            libxml_use_internal_errors($previous);
        }
        if (!$loaded || $doc->documentElement === null) {
            $detail = $error !== false ? trim($error->message) : 'no root element';
            throw new BuzzApiException("Could not parse the XML response: {$detail}");
        }
        $root = $doc->documentElement;
        return [$root->localName => self::xmlToArray($root)];
    }

    /**
     * Like parseEnvelope(), but returns null instead of throwing when the body
     * is not XML or JSON (for example, an HTML error page from a proxy).
     */
    private function tryParseEnvelope(string $body, ?string $contentType): ?array
    {
        try {
            return $this->parseEnvelope($body, $contentType);
        } catch (BuzzApiException $e) {
            return null;
        }
    }

    private static function xmlToArray(\DOMElement $element): array
    {
        $result = [];
        foreach ($element->attributes as $attribute) {
            $result[$attribute->localName] = $attribute->value;
        }

        // Group child elements by name, keeping first-seen order.
        $groups = [];
        $text = '';
        foreach ($element->childNodes as $child) {
            if ($child instanceof \DOMElement) {
                $groups[$child->localName][] = self::xmlToArray($child);
            } elseif ($child->nodeType === XML_TEXT_NODE || $child->nodeType === XML_CDATA_SECTION_NODE) {
                $text .= $child->nodeValue;
            }
        }
        foreach ($groups as $name => $children) {
            $result[$name] = count($children) === 1 ? $children[0] : $children;
        }

        if (trim($text) !== '') {
            $result['$value'] = $text;
        }
        return $result;
    }

    /** The envelope code: response.code for a normal response. */
    private static function responseCode(?array $node): ?string
    {
        if ($node === null) {
            return null;
        }
        if (isset($node['response']) && is_array($node['response'])) {
            return self::stringOrNull($node['response']['code'] ?? null);
        }
        return self::stringOrNull($node['code'] ?? null);
    }

    /** The code of a batch or multi-object item. */
    private static function itemCode($item): ?string
    {
        return is_array($item) ? self::stringOrNull($item['code'] ?? null) : null;
    }

    private static function stringOrNull($value): ?string
    {
        return is_scalar($value) ? (string) $value : null;
    }

    private static function isThrottleCode(?string $code): bool
    {
        return self::codeInList($code, self::THROTTLE_CODES);
    }

    /**
     * Whether an envelope code is in a list of codes, ignoring case.
     *
     * @param list<string> $codes
     */
    private static function codeInList(?string $code, array $codes): bool
    {
        if ($code === null) {
            return false;
        }
        foreach ($codes as $listed) {
            if (strcasecmp($code, $listed) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * The HTTP status to report for a throttle: the real one when the server
     * sent 429/503, otherwise the status the envelope code stands for (the
     * server wraps these in HTTP 200 for legacy clients).
     */
    private static function throttleStatusCode(int $status, ?string $code): int
    {
        if ($status === 429 || $status === 503) {
            return $status;
        }
        return self::codeInList($code, self::THROTTLE_CODES_503) ? 503 : 429;
    }

    /**
     * The per-item results of a batch or multi-object command
     * (responses.response).  JSON always gives a list; a single item converted
     * from XML is an associative array.
     *
     * @return array<int,mixed>
     */
    private static function childResponses(?array $response): array
    {
        $items = $response['responses']['response'] ?? null;
        if (!is_array($items) || $items === []) {
            return [];
        }
        return self::isList($items) ? $items : [$items];
    }

    /**
     * Count throttled items at any depth, since a batch item can itself be a
     * multi-object command with per-row results.
     */
    private static function countThrottledItems(?array $response): int
    {
        $count = 0;
        foreach (self::childResponses($response) as $item) {
            if (self::isThrottleCode(self::itemCode($item))) {
                $count++;
            }
            if (is_array($item)) {
                $count += self::countThrottledItems($item);
            }
        }
        return $count;
    }

    // ── Throttling ─────────────────────────────────────────────────────────────
    /**
     * Back off the whole client when a successful batch or multi-object
     * response contains throttled items, so resubmitting them (and any other
     * requests on this client) waits as the server asked.
     */
    private function extendThrottleWindowForThrottledItems(?array $envelope, array $headers): void
    {
        $response = (isset($envelope['response']) && is_array($envelope['response']))
            ? $envelope['response']
            : $envelope;
        $throttled = self::countThrottledItems($response);
        if ($throttled === 0) {
            return;
        }
        $wait = min(
            self::MAX_SERVER_DIRECTED_WAIT_SECONDS,
            self::throttleWait(self::serverDirectedWait($headers), self::INITIAL_WAIT_SECONDS)
        );
        $this->log('warning', sprintf(
            '%d items in the response were throttled; backing off %dms before the next request',
            $throttled, (int) ($wait * 1000)
        ));
        $this->extendThrottleWindow($wait);
    }

    /** Move the client-wide throttle window out to at least $wait seconds from now (never back). */
    private function extendThrottleWindow(float $wait): void
    {
        $this->throttledUntil = max($this->throttledUntil, microtime(true) + $wait);
    }

    /** Wait until the client-wide throttle window has passed. */
    private function waitForThrottleWindow(): void
    {
        $remaining = $this->throttledUntil - microtime(true);
        if ($remaining > 0) {
            $this->log('debug', sprintf(
                "Waiting %dms for the server's throttle window to pass", (int) ($remaining * 1000)
            ));
            self::sleepSeconds($remaining);
        }
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function statusAllowsRetry(int $status): bool
    {
        return !in_array($status, self::NO_RETRY_STATUS, true);
    }

    /**
     * The wait the server asked for: Retry-After (delta-seconds or HTTP date)
     * first, then X-RateLimit-Reset, which Buzz sends as seconds until the
     * rate-limit window resets (not a Unix time).  The server sends these on
     * throttled responses whether the HTTP status is 200 or 429/503.
     *
     * @return float|null Seconds, or null if the server gave none.
     */
    private static function serverDirectedWait(array $headers): ?float
    {
        $seconds = self::retryAfterSeconds($headers['retry-after'] ?? null);
        if ($seconds !== null && $seconds > 0) {
            return $seconds;
        }
        $reset = trim((string) ($headers['x-ratelimit-reset'] ?? ''));
        if ($reset !== '' && ctype_digit($reset) && (int) $reset > 0) {
            return (float) $reset;
        }
        return null;
    }

    /**
     * How long to back off from a throttle: the server-directed wait if there
     * is one (never less than the current exponential base), otherwise
     * exponential backoff with jitter.  A server-directed wait is not capped
     * here; the caller compares it with MAX_SERVER_DIRECTED_WAIT_SECONDS rather
     * than retrying before the server said to.
     */
    private static function throttleWait(?float $serverWait, float $baseWait): float
    {
        if ($serverWait !== null) {
            return max($serverWait, $baseWait);
        }
        return min(self::MAX_RETRY_WAIT_SECONDS, $baseWait + self::jitter());
    }

    /** Backoff from a Retry-After header, else exponential backoff with jitter. */
    private static function waitFromRetryHeader(array $headers, float $baseWait): float
    {
        $seconds = self::retryAfterSeconds($headers['retry-after'] ?? null);
        if ($seconds !== null) {
            return min(self::MAX_RETRY_WAIT_SECONDS, max($baseWait, $seconds));
        }
        return min(self::MAX_RETRY_WAIT_SECONDS, $baseWait + self::jitter());
    }

    /** Parse a Retry-After value (delta-seconds or an HTTP date) into seconds. */
    private static function retryAfterSeconds(?string $retryAfter): ?float
    {
        if ($retryAfter === null || $retryAfter === '') {
            return null;
        }
        $retryAfter = trim($retryAfter);
        if (ctype_digit($retryAfter)) {
            return (float) $retryAfter;
        }
        $when = strtotime($retryAfter);
        if ($when === false) {
            return null;
        }
        return max(0.0, (float) ($when - time()));
    }

    private static function jitter(): float
    {
        return random_int(1, 1000) / 1000.0;
    }

    private static function sleepSeconds(float $seconds): void
    {
        usleep((int) round($seconds * 1_000_000));
    }

    private static function redactQueryParam(string $uri, string $paramName): string
    {
        $q = strpos($uri, '?');
        if ($q === false) {
            return $uri;
        }
        $kept = [];
        foreach (explode('&', substr($uri, $q + 1)) as $pair) {
            if (stripos($pair, $paramName . '=') !== 0) {
                $kept[] = $pair;
            }
        }
        return $kept ? substr($uri, 0, $q) . '?' . implode('&', $kept) : substr($uri, 0, $q);
    }

    /** Deep-copy a decoded JSON value, masking any sensitive field values. */
    private static function cloneAndRedact($node)
    {
        if (!is_array($node)) {
            return $node;
        }
        $result = [];
        foreach ($node as $key => $value) {
            if (is_string($key) && in_array($key, self::SENSITIVE_FIELDS, true)) {
                $result[$key] = '[REDACTED]';
            } else {
                $result[$key] = self::cloneAndRedact($value);
            }
        }
        return $result;
    }

    private static function isList($value): bool
    {
        if (!is_array($value)) {
            return false;
        }
        return array_keys($value) === range(0, count($value) - 1);
    }
}
