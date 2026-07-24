<?php

declare(strict_types=1);

/**
 * Register an RSA public key with Buzz for OAuth 2.0 authentication.
 *
 * Usage:
 *     php scripts/register-buzz-oauth-key.php -s SERVER_URL -u USER_ID -k KID -p PUBLIC_KEY_PATH [-t TOKEN]
 *
 * The admin Bearer token is read (in order of preference) from:
 *     -t/--token,  the BUZZ_ADMIN_TOKEN environment variable,  or an interactive prompt.
 *
 * PUTting an existing kid REPLACES the key immediately — use a new kid to rotate.
 */

require_once __DIR__ . '/common.php';

function main(array $argv): int
{
    $server = $token = $userId = $kid = $publicKeyPath = '';
    for ($i = 1; $i < count($argv); $i++) {
        switch ($argv[$i]) {
            case '-s': case '--server':     $server = $argv[++$i] ?? ''; break;
            case '-t': case '--token':      $token = $argv[++$i] ?? ''; break;
            case '-u': case '--user-id':    $userId = $argv[++$i] ?? ''; break;
            case '-k': case '--kid':        $kid = $argv[++$i] ?? ''; break;
            case '-p': case '--public-key': $publicKeyPath = $argv[++$i] ?? ''; break;
            case '-h': case '--help':
                echo "Usage: php scripts/register-buzz-oauth-key.php -s URL -u USER_ID -k KID -p PUBLIC_KEY [-t TOKEN]\n";
                return 0;
        }
    }

    if ($server === '' || $userId === '' || $kid === '' || $publicKeyPath === '') {
        fwrite(STDERR, "Error: -s, -u, -k and -p are all required.\n");
        return 1;
    }
    $server = rtrim($server, '/');
    if (!preg_match('/^[A-Za-z0-9._-]{1,128}$/', $kid)) {
        fwrite(STDERR, "Error: invalid kid. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.\n");
        return 1;
    }
    if (!is_file($publicKeyPath)) {
        fwrite(STDERR, "Error: public key file not found: {$publicKeyPath}\n");
        return 1;
    }
    $pem = (string) file_get_contents($publicKeyPath);
    if (strpos($pem, 'BEGIN PUBLIC KEY') === false) {
        fwrite(STDERR, "Error: file is not a SubjectPublicKeyInfo PEM ('-----BEGIN PUBLIC KEY-----').\n");
        return 1;
    }

    if ($token === '') {
        $envToken = getenv('BUZZ_ADMIN_TOKEN');
        $token = $envToken !== false && $envToken !== '' ? (string) $envToken
            : prompt_password('Admin Bearer token');
    }
    if ($token === '') {
        fwrite(STDERR, "Error: admin token is required.\n");
        return 1;
    }

    echo "Registering public key...\n";
    echo "  URL  : {$server}/api/users/{$userId}/keys/{$kid}\n";
    echo "  Kid  : {$kid}\n";
    echo '  File : ' . realpath($publicKeyPath) . "\n\n";

    [$status, $body] = register_public_key($server, $userId, $kid, $pem, $token);
    return report_status($status, $body, $userId, $kid);
}

function report_status(int $status, string $body, string $userId, string $kid): int
{
    if ($status === 204) {
        echo "Public key registered successfully (HTTP 204).\n\n";
        echo "Configure your application:\n";
        echo "  oauthUserId = {$userId}\n";
        echo "  oauthKid    = {$kid}\n";
        return 0;
    }
    if ($status === 400) {
        fwrite(STDERR, "Error: HTTP 400 Bad Request\n");
        fwrite(STDERR, "  - Public key must be SPKI PEM and at least 2048 bits.\n");
        fwrite(STDERR, "  - Account {$userId} must have been created with type=applicationidentity.\n");
    } elseif ($status === 401 || $status === 403) {
        fwrite(STDERR, "Error: HTTP {$status} — admin token lacks Update User rights on account {$userId}.\n");
    } elseif ($status === 404) {
        fwrite(STDERR, "Error: HTTP 404 — server URL or user id not found.\n");
    } else {
        fwrite(STDERR, "Error: unexpected HTTP {$status}\n");
    }
    if ($body !== '') {
        fwrite(STDERR, "Response: {$body}\n");
    }
    return 1;
}

if (realpath($argv[0] ?? '') === realpath(__FILE__)) {
    exit(main($argv));
}
