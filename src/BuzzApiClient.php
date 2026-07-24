<?php

declare(strict_types=1);

namespace Agilix\BuzzApi;

/**
 * Makes requests to a Buzz API server, authenticating with OAuth 2.0 JWT client
 * credentials (RFC 6749 + RFC 7523).  The client obtains and refreshes Bearer
 * access tokens automatically, retries transient failures with exponential
 * backoff, and honours rate-limit headers.
 *
 * Requires PHP 7.4+ with the bundled openssl, curl, and json extensions.
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
        400, 401, 402, 403, 405, 406, 407, 410, 411, 412, 413, 414, 415, 416,
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
     * @return array|null The decoded JSON response, or null if the body was empty.
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

        [$status, $body] = $this->requestWithRetry($method, $cmd, $params, $content, $includeToken);
        $node = $this->parseJson($body);
        $this->traceResponse($node);

        // If the token expired or was revoked, re-authenticate and retry once.
        if ($includeToken && $this->token !== null && self::responseCode($node) === 'NoAuthentication') {
            $this->log('debug', 'Re-authenticating because the request returned code "NoAuthentication"');
            $this->authenticateOAuth();
            [$status, $body] = $this->requestWithRetry($method, $cmd, $params, $content, $includeToken);
            $node = $this->parseJson($body);
            $this->traceResponse($node);
        }

        return $node;
    }

    /**
     * Verify that a Buzz JSON response indicates success.
     *
     * @param array|null $responseJson         The decoded response to check.
     * @param bool       $checkChildResponses  Also verify nested child responses (batch APIs).
     * @return array The verified response node.
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

        if (($toVerify['code'] ?? null) !== 'OK') {
            $redacted = json_encode(self::cloneAndRedact($responseJson));
            $this->log('error', "Buzz API call failed. Expected response.code to be OK, found: {$redacted}");
            throw new BuzzApiException("Buzz API call failed. Expected response.code to be OK, found: {$redacted}");
        }

        if ($checkChildResponses && isset($toVerify['responses']['response'])) {
            $children = $toVerify['responses']['response'];
            if (self::isList($children)) {
                foreach ($children as $child) {
                    $this->verifyResponse($child);
                }
            } elseif (is_array($children)) {
                $this->verifyResponse($children);
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
            // A fresh assertion is built on every attempt: JWTs expire in two
            // minutes and a long backoff can push a reused assertion past exp.
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

            if (($status === 429 || $status === 503) && $retriesRemaining > 0) {
                $wait = self::waitFromResponse($headers, $baseWait);
                $this->log('warning', sprintf(
                    'OAuth token request rate-limited (%d), backing off %dms, %d retries remaining',
                    $status, (int) ($wait * 1000), $retriesRemaining
                ));
                self::sleepSeconds($wait);
                $retriesRemaining--;
                $baseWait *= 2;
                continue;
            }

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
                if ($retriesRemaining > 0 && self::statusAllowsRetry($status)) {
                    $wait = self::waitFromRetryHeader($headers, $baseWait);
                    $this->log('debug', "OAuth token request retrying after HTTP {$status}");
                    self::sleepSeconds($wait);
                    $retriesRemaining--;
                    $baseWait *= 2;
                    continue;
                }
                $this->log('error', "OAuth token request failed: {$status} {$body}");
                throw new BuzzApiException("OAuth token request failed (HTTP {$status}): {$body}");
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
     * @return array{0:int,1:string} [httpStatus, responseBody]
     */
    private function requestWithRetry(
        string $method,
        ?string $cmd,
        array $params,
        ?string $content,
        bool $includeToken
    ): array {
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
            $this->traceRequest($url);
            [$status, $body, $respHeaders, $errno] = $this->curl($method, $url, $content, $headers);

            if ($status === 429 || $status === 503) {
                if ($retriesRemaining > 0) {
                    $wait = self::waitFromResponse($respHeaders, $baseWait);
                    $this->log('warning', sprintf(
                        'Request rate/time limited (%d), backing off %dms, %d retries remaining',
                        $status, (int) ($wait * 1000), $retriesRemaining
                    ));
                    self::sleepSeconds($wait);
                    $retriesRemaining--;
                    $baseWait *= 2;
                    continue;
                }
                throw new BuzzApiException("Server returned {$status} (rate/time limited). No retries remaining.");
            }

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

            if ($status < 200 || $status >= 300) {
                if ($retriesRemaining > 0 && self::statusAllowsRetry($status)) {
                    $wait = self::waitFromRetryHeader($respHeaders, $baseWait);
                    $this->log('debug', "Retrying {$cmd} after HTTP {$status}");
                    self::sleepSeconds($wait);
                    $retriesRemaining--;
                    $baseWait *= 2;
                    continue;
                }
                throw new BuzzApiException("Request to " . ($cmd ?? $url) . " failed: HTTP {$status}");
            }

            return [$status, $body];
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

    private static function responseCode(?array $node): ?string
    {
        if ($node === null) {
            return null;
        }
        if (isset($node['response']) && is_array($node['response'])) {
            return $node['response']['code'] ?? null;
        }
        return $node['code'] ?? null;
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function statusAllowsRetry(int $status): bool
    {
        return !in_array($status, self::NO_RETRY_STATUS, true);
    }

    /** Backoff from rate-limit headers: Retry-After, else X-RateLimit-Reset. */
    private static function waitFromResponse(array $headers, float $baseWait): float
    {
        $seconds = self::retryAfterSeconds($headers['retry-after'] ?? null);
        if ($seconds !== null && $seconds > 0) {
            return self::clamp($seconds, $baseWait, self::MAX_RETRY_WAIT_SECONDS);
        }
        $reset = $headers['x-ratelimit-reset'] ?? null;
        if ($reset !== null && ctype_digit((string) $reset) && (int) $reset > 0) {
            return self::clamp((float) $reset, $baseWait, self::MAX_RETRY_WAIT_SECONDS);
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

    private static function clamp(float $value, float $low, float $high): float
    {
        return max($low, min($high, $value));
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
