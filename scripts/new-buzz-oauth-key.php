<?php

declare(strict_types=1);

/**
 * Generate an RSA key pair for Buzz OAuth 2.0 authentication.
 *
 * Usage:
 *     php scripts/new-buzz-oauth-key.php [--out DIR] [--bits N] [--force]
 *
 * Outputs:
 *     private_key.pem  — RSA private key  (keep secret; never commit to source control)
 *     public_key.pem   — RSA public key   (register with register-buzz-oauth-key.php)
 *
 * Uses the bundled openssl extension.  No external OpenSSL binary needed.
 *
 * SECURITY: add private_key.pem to .gitignore immediately.  For production,
 * store the private key in a secrets manager.
 */

require_once __DIR__ . '/common.php';

const BUZZ_MIN_KEY_BITS = 2048;

/**
 * Generate an RSA key pair; write private_key.pem (0600) and public_key.pem (SPKI).
 *
 * @return array{0:string,1:string} absolute [privateKeyPath, publicKeyPath]
 */
function generate_key_pair(string $outDir, int $bits = BUZZ_MIN_KEY_BITS, bool $overwrite = false): array
{
    if ($bits < BUZZ_MIN_KEY_BITS) {
        throw new RuntimeException('Key size must be at least ' . BUZZ_MIN_KEY_BITS . ' bits (Buzz minimum).');
    }
    if (!is_dir($outDir) && !mkdir($outDir, 0700, true) && !is_dir($outDir)) {
        throw new RuntimeException("Could not create output directory: {$outDir}");
    }
    $privPath = realpath($outDir) . DIRECTORY_SEPARATOR . 'private_key.pem';
    $pubPath = realpath($outDir) . DIRECTORY_SEPARATOR . 'public_key.pem';

    if (!$overwrite && (is_file($privPath) || is_file($pubPath))) {
        throw new RuntimeException("Key file(s) already exist in {$outDir}.");
    }

    $args = ['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
    $res = @openssl_pkey_new($args);
    $exportArgs = null;
    if ($res === false) {
        // On some platforms (notably Windows) OpenSSL cannot locate a default
        // openssl.cnf.  Retry with a minimal config file so key generation is
        // self-contained and does not depend on an OPENSSL_CONF environment var.
        $cnf = buzz_temp_openssl_config();
        $exportArgs = ['config' => $cnf];
        $res = openssl_pkey_new($args + ['config' => $cnf]);
        if ($res === false) {
            throw new RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }
    }

    $privPem = '';
    if (!openssl_pkey_export($res, $privPem, null, $exportArgs)) {
        throw new RuntimeException('openssl_pkey_export failed: ' . openssl_error_string());
    }
    $details = openssl_pkey_get_details($res);
    if ($details === false || !isset($details['key'])) {
        throw new RuntimeException('Could not extract the public key.');
    }
    $pubPem = $details['key'];  // SubjectPublicKeyInfo PEM — the format Buzz expects.

    // Create the private key file with owner-only permissions from the start.
    $old = umask(0077);
    file_put_contents($privPath, $privPem);
    umask($old);
    @chmod($privPath, 0600);
    file_put_contents($pubPath, $pubPem);

    return [$privPath, $pubPath];
}

/**
 * Write a minimal OpenSSL config to a temp file and return its path (cached).
 * Used as a fallback when OpenSSL cannot find a default openssl.cnf.
 */
function buzz_temp_openssl_config(): string
{
    static $path = null;
    if ($path !== null) {
        return $path;
    }
    // Use the tempnam path directly (OpenSSL ignores the extension) so no
    // orphan file is left behind.
    $path = tempnam(sys_get_temp_dir(), 'buzz_openssl_');
    file_put_contents($path, "[req]\ndistinguished_name = req_distinguished_name\n[req_distinguished_name]\n");
    register_shutdown_function(static function () use ($path) {
        @unlink($path);
    });
    return $path;
}

function parse_args(array $argv): array
{
    $opts = ['out' => '.', 'bits' => BUZZ_MIN_KEY_BITS, 'force' => false];
    for ($i = 1; $i < count($argv); $i++) {
        switch ($argv[$i]) {
            case '-o': case '--out':   $opts['out'] = $argv[++$i] ?? '.'; break;
            case '-b': case '--bits':  $opts['bits'] = (int) ($argv[++$i] ?? BUZZ_MIN_KEY_BITS); break;
            case '-f': case '--force': $opts['force'] = true; break;
            case '-h': case '--help':
                echo "Usage: php scripts/new-buzz-oauth-key.php [--out DIR] [--bits N] [--force]\n";
                exit(0);
        }
    }
    return $opts;
}

// Only run when executed directly (not when required by setup).
if (realpath($argv[0] ?? '') === realpath(__FILE__)) {
    $opts = parse_args($argv);
    if (!$opts['force'] && is_file(rtrim($opts['out'], '/\\') . '/private_key.pem')) {
        if (!confirm('Key files already exist and will be overwritten.  Continue?')) {
            echo "Aborted.\n";
            exit(0);
        }
        $opts['force'] = true;
    }
    try {
        [$privPath, $pubPath] = generate_key_pair($opts['out'], $opts['bits'], $opts['force']);
    } catch (RuntimeException $e) {
        fwrite(STDERR, 'Error: ' . $e->getMessage() . "\n");
        exit(1);
    }
    echo "\nRSA key pair generated ({$opts['bits']} bits):\n";
    echo "  Private key : {$privPath}\n";
    echo "  Public key  : {$pubPath}\n\n";
    echo "Next step: register the public key with Buzz.\n";
    echo "  php scripts/register-buzz-oauth-key.php -s https://backgroundapi.agilixbuzz.com -u <userid> -k <kid> -p public_key.pem\n\n";
    echo "IMPORTANT: Never commit private_key.pem to source control.\n";
}
