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
// /cmd/* endpoints authenticate a session token via the _token query parameter.
// /api/* (REST) endpoints authenticate via the Authorization: Bearer header.

/**
 * @return array<string,mixed>|null
 */
function buzz_post(string $server, string $cmd, $body, ?string $token = null): ?array
{
    $url = "{$server}/cmd/{$cmd}";
    if ($token !== null) {
        $url .= '?' . http_build_query(['_token' => $token]);
    }
    [$status, $decoded] = buzz_http('POST', $url, json_encode($body),
        ['Content-Type: application/json', 'Accept: application/json']);
    return $decoded;
}

/**
 * @param array<string,mixed> $params
 * @return array<string,mixed>|null
 */
function buzz_get(string $server, string $cmd, array $params = [], ?string $token = null): ?array
{
    if ($token !== null) {
        $params['_token'] = $token;
    }
    $url = "{$server}/cmd/{$cmd}";
    if ($params) {
        $url .= '?' . http_build_query($params);
    }
    [$status, $decoded] = buzz_http('GET', $url, null, ['Accept: application/json']);
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

        // MFA branch.  Exact command/field names depend on server configuration.
        if ($code !== '' && preg_match('/(factor|mfa|otp|challenge|verify|multifactor)/i', $code)) {
            echo " MFA required.\n";
            $mfa = prompt_required('MFA / one-time code', '', 'BUZZ_ADMIN_MFA');
            $partial = $resp['response']['token'] ?? ($resp['token'] ?? '');
            $resp = buzz_post($server, 'verifylogin',
                ['request' => ['cmd' => 'verifylogin', 'token' => $partial, 'code' => $mfa]]);
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
