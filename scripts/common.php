<?php

declare(strict_types=1);

/**
 * Shared helpers for the Buzz API sample setup/run/cleanup scripts.
 *
 * These talk to the Buzz API for one-time setup tasks (admin login, key
 * registration, account management).  They use the legacy `login3` command only
 * to obtain a short-lived admin session token for setup — the sample
 * application itself never uses login3, only OAuth.
 *
 * Interactive prompts fall back to environment variables when set, so the
 * scripts can run unattended (useful for automated testing):
 *   BUZZ_SERVER_URL, BUZZ_ADMIN_USERNAME, BUZZ_ADMIN_PASSWORD, BUZZ_ADMIN_MFA
 */

require_once __DIR__ . '/../bootstrap.php';

const BUZZ_HTTP_TIMEOUT_MS = 60000;

// ── Console output ───────────────────────────────────────────────────────────
function out_section(string $title): void
{
    echo "\n--- {$title} " . str_repeat('-', max(0, 50 - strlen($title))) . "\n";
}

function out_info(string $msg): void
{
    echo "  {$msg}\n";
}

function fail(string $msg): void
{
    fwrite(STDERR, "\nError: {$msg}\n");
    exit(1);
}

// ── Prompts (with environment-variable fallbacks) ──────────────────────────────
function prompt_required(string $label, string $default = '', ?string $env = null): string
{
    if ($env !== null && getenv($env) !== false && getenv($env) !== '') {
        return (string) getenv($env);
    }
    while (true) {
        $suffix = $default !== '' ? " [{$default}]" : '';
        $value = read_line("{$label}{$suffix}: ");
        if ($value === null) {  // EOF
            if ($default !== '') {
                return $default;
            }
            fail("'{$label}' is required but no value was provided" . ($env ? " (set {$env})" : ''));
        }
        $value = trim($value);
        if ($value === '') {
            $value = $default;
        }
        if ($value !== '') {
            return $value;
        }
        echo "  (required)\n";
    }
}

function prompt_optional(string $label, ?string $env = null): string
{
    if ($env !== null && getenv($env) !== false && getenv($env) !== '') {
        return (string) getenv($env);
    }
    $value = read_line("{$label} (optional, press Enter to skip): ");
    return $value === null ? '' : trim($value);
}

function prompt_password(string $label, ?string $env = null): string
{
    if ($env !== null && getenv($env) !== false && getenv($env) !== '') {
        return (string) getenv($env);
    }
    // Hide input on Unix-like systems via stty; on Windows, fall back to visible input.
    $isWindows = stripos(PHP_OS, 'WIN') === 0;
    if (!$isWindows && function_exists('shell_exec') && @shell_exec('command -v stty') !== null) {
        echo "{$label}: ";
        @shell_exec('stty -echo');
        $value = read_line('');
        @shell_exec('stty echo');
        echo "\n";
        return $value === null ? '' : trim($value);
    }
    $value = read_line("{$label}: ");
    if ($value === null) {
        fail("'{$label}' is required but no value was provided" . ($env ? " (set {$env})" : ''));
    }
    return trim($value);
}

function confirm(string $label, bool $defaultYes = false): bool
{
    $suffix = $defaultYes ? '[Y/n]' : '[y/N]';
    $value = read_line("{$label} {$suffix} ");
    if ($value === null || trim($value) === '') {
        return $defaultYes;
    }
    return stripos(trim($value), 'y') === 0;
}

/** Read a line from STDIN.  Returns null on EOF. */
function read_line(string $prompt): ?string
{
    if ($prompt !== '') {
        echo $prompt;
    }
    $line = fgets(STDIN);
    return $line === false ? null : rtrim($line, "\r\n");
}

// ── Buzz API calls ──────────────────────────────────────────────────────────
// Session tokens travel in an Authorization: Bearer header on both /cmd/* and /api/*
// endpoints.  A _token query parameter is also accepted by /cmd/*, but a credential in
// a URL is recorded by server and proxy access logs.
// Buzz returns XML unless JSON is requested via Accept.

/**
 * @param list<string> $extra
 * @return list<string>
 */
function buzz_auth_headers(?string $token, array $extra = []): array
{
    $headers = ['Accept: application/json'];
    if ($token !== null && $token !== '') {
        $headers[] = "Authorization: Bearer {$token}";
    }
    return array_merge($headers, $extra);
}

/**
 * @return array<string,mixed>|null
 */
function buzz_post(string $server, string $cmd, $body, ?string $token = null): ?array
{
    $url = "{$server}/cmd/{$cmd}";
    [$status, $decoded] = buzz_http('POST', $url, json_encode($body),
        buzz_auth_headers($token, ['Content-Type: application/json']));
    return $decoded;
}

/**
 * @param array<string,mixed> $params
 * @return array<string,mixed>|null
 */
function buzz_get(string $server, string $cmd, array $params = [], ?string $token = null): ?array
{
    $url = "{$server}/cmd/{$cmd}";
    if ($params) {
        $url .= '?' . http_build_query($params);
    }
    [$status, $decoded] = buzz_http('GET', $url, null, buzz_auth_headers($token));
    return $decoded;
}

/**
 * PUT a public key to /api/users/{id}/keys/{kid}.
 * @return array{0:int,1:string} [httpStatus, body]
 */
function register_public_key(string $server, string $userId, string $kid, string $publicKeyPem, string $token): array
{
    $url = "{$server}/api/users/{$userId}/keys/{$kid}";
    [$status, , $raw] = buzz_http('PUT', $url, $publicKeyPem,
        ["Authorization: Bearer {$token}", 'Content-Type: application/x-pem-file']);
    return [$status, $raw];
}

/**
 * @return array{0:int,1:string} [httpStatus, body]
 */
function delete_public_key(string $server, string $userId, string $kid, string $token): array
{
    $url = "{$server}/api/users/{$userId}/keys/{$kid}";
    [$status, , $raw] = buzz_http('DELETE', $url, null, ["Authorization: Bearer {$token}"]);
    return [$status, $raw];
}

/**
 * Perform a single HTTP request.  Returns [status, decodedArrayOrNull, rawBody].
 *
 * @param string[] $headers
 * @return array{0:int,1:(array<string,mixed>|null),2:string}
 */
function buzz_http(string $method, string $url, ?string $body, array $headers): array
{
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT_MS => BUZZ_HTTP_TIMEOUT_MS,
        CURLOPT_HTTPHEADER => $headers,
    ]);
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $raw = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $errno = curl_errno($ch);
    $err = curl_error($ch);
    curl_close($ch);

    if ($errno !== 0) {
        fwrite(STDERR, "  curl error {$errno} for {$url}: {$err}\n");
        return [$status, null, ''];
    }
    $rawStr = is_string($raw) ? $raw : '';
    $decoded = json_decode($rawStr, true);
    return [$status, is_array($decoded) ? $decoded : null, $rawStr];
}

/**
 * @param array<string,mixed>|null $resp
 */
function response_code(?array $resp): string
{
    if ($resp === null) {
        return '';
    }
    if (isset($resp['response']) && is_array($resp['response']) && isset($resp['response']['code'])) {
        return (string) $resp['response']['code'];
    }
    return (string) ($resp['code'] ?? '');
}

/**
 * @param array<string,mixed>|null $resp
 */
function response_message(?array $resp): string
{
    $inner = (is_array($resp) && isset($resp['response']) && is_array($resp['response'])) ? $resp['response'] : ($resp ?? []);
    return (string) ($inner['message'] ?? '');
}

/**
 * The per-entity result of a multi-object command (CreateUsers2, DeleteUsers).
 *
 * Those commands report each entity's outcome under response.responses.response, while
 * the OUTER code is OK whenever the request was merely well formed.  A per-entity
 * AccessDenied therefore arrives inside an "OK" envelope, so the outer code alone
 * cannot tell you whether the entity was actually created or deleted.  'code' is ''
 * when the response carries no per-entity result at all.
 *
 * @return array{code:string,message:string,userid:string}
 */
function item_result(?array $resp): array
{
    $empty = ['code' => '', 'message' => '', 'userid' => ''];
    $inner = (is_array($resp) && isset($resp['response']) && is_array($resp['response'])) ? $resp['response'] : ($resp ?? []);
    if (!is_array($inner) || !isset($inner['responses']) || !is_array($inner['responses'])) {
        return $empty;
    }
    $node = $inner['responses']['response'] ?? null;
    if (is_array($node) && array_is_list($node)) {
        $node = $node[0] ?? null;
    }
    if (!is_array($node)) {
        return $empty;
    }
    return [
        'code'    => (string) ($node['code'] ?? ''),
        'message' => (string) ($node['message'] ?? ''),
        'userid'  => (string) ($node['user']['userid'] ?? ''),
    ];
}

/**
 * The short-lived token login3 returns alongside SecondFactorRequired.
 *
 * Observed shape: response.token, duplicated at response.body.token.  There is no
 * "user" node on that response, so response.user.token (where the session token lives
 * on a *successful* login) does not exist yet.  remembermfa.token is deliberately
 * ignored: it remembers a device and cannot complete this login.
 */
function second_factor_token(?array $resp): string
{
    $inner = (is_array($resp) && isset($resp['response']) && is_array($resp['response'])) ? $resp['response'] : ($resp ?? []);
    if (!is_array($inner)) {
        return '';
    }
    foreach ([$inner['user']['token'] ?? null, $inner['token'] ?? null, $inner['body']['token'] ?? null] as $candidate) {
        if (is_string($candidate) && $candidate !== '') {
            return $candidate;
        }
    }
    return '';
}

// ── Admin login (login3, with optional MFA) ─────────────────────────────────────
function admin_login(string $server): string
{
    while (true) {
        $username = read_admin_username();
        $password = prompt_password('Admin password', 'BUZZ_ADMIN_PASSWORD');

        echo 'Logging in...';
        $resp = buzz_post($server, 'login3',
            ['request' => ['cmd' => 'login3', 'username' => $username, 'password' => $password]]);
        $code = response_code($resp);

        // Multi-factor authentication.  login3 answers SecondFactorRequired when the
        // password was correct but the account has MFA configured, and returns a
        // short-lived token that is presented in an Authorization: Bearer header to
        // secondfactorauthenticate, which returns the real session token.  Putting the
        // token in the request body instead is ignored: AccessDenied userId='-1'.
        //   https://api.agilixbuzz.com/docs/entry/Command/Login3.md
        //   https://api.agilixbuzz.com/docs/entry/Command/SecondFactorAuthenticate.md
        if ($code === 'SecondFactorConfigurationNowRequired') {
            echo "\n  This account must configure multi-factor authentication before it can\n";
            echo "  be used.  Complete MFA setup in Buzz, then re-run this script.\n";
            if (getenv('BUZZ_ADMIN_PASSWORD') !== false) {
                fail('Admin account requires multi-factor authentication setup.');
            }
            echo "  Press Ctrl+C to abort.\n\n";
            continue;
        }

        if ($code === 'SecondFactorRequired') {
            echo " multi-factor authentication required.\n";
            $partial = second_factor_token($resp);
            if ($partial === '') {
                echo "\n  Buzz asked for a second factor but no token could be found in its reply.\n";
                if (getenv('BUZZ_ADMIN_PASSWORD') !== false) {
                    fail('No second-factor token was returned.');
                }
                echo "  Press Ctrl+C to abort.\n\n";
                continue;
            }
            $otp = prompt_required('One-time code from your authenticator app or email', '', 'BUZZ_ADMIN_MFA');
            $resp = buzz_post($server, 'secondfactorauthenticate',
                ['request' => ['cmd' => 'secondfactorauthenticate', 'otp' => $otp]], $partial);
            $code = response_code($resp);
        }

        if ($code !== 'OK') {
            $msg = response_message($resp);
            echo "\n  Login failed (code: {$code})" . ($msg !== '' ? ": {$msg}" : '') . "\n";
            if (getenv('BUZZ_ADMIN_PASSWORD') !== false) {
                fail('Login failed with credentials from environment variables.');
            }
            echo "  Please check your credentials and try again.  Press Ctrl+C to abort.\n\n";
            continue;
        }

        $token = $resp['response']['user']['token'] ?? ($resp['user']['token'] ?? '');
        if ($token === '') {
            echo "\n  Login succeeded but no token was returned.  Press Ctrl+C to abort.\n\n";
            continue;
        }
        echo " OK\n";
        return (string) $token;
    }
}

function read_admin_username(): string
{
    $env = getenv('BUZZ_ADMIN_USERNAME');
    if ($env !== false && $env !== '') {
        return (string) $env;
    }
    while (true) {
        $value = read_line('Admin username (userspace/username, e.g. myschool/admin): ');
        if ($value !== null && preg_match('#^[^/]+/[^/]+$#', trim($value))) {
            return trim($value);
        }
        echo "  Username must be in userspace/username format.\n";
    }
}
