<?php

declare(strict_types=1);

/**
 * Entry point for the Buzz API sample.
 *
 * If setup has not been completed (buzz-config.php missing or the private key
 * file not readable), the interactive setup runs first.  Then the read-only
 * sample runs.
 *
 * Usage:
 *     php scripts/run-buzz-sample.php [--setup]
 *
 *     --setup   Force re-running setup even if already configured.
 */

require_once __DIR__ . '/common.php';

function setup_complete(): bool
{
    if (!is_file(BUZZ_CONFIG_FILE)) {
        return false;
    }
    $config = require BUZZ_CONFIG_FILE;
    if (!is_array($config)) {
        return false;
    }
    foreach (BUZZ_CONFIG_REQUIRED as $key) {
        if (empty($config[$key])) {
            return false;
        }
    }
    return is_file((string) $config['privateKeyPath']);
}

$force = in_array('--setup', $argv, true);

if ($force || !setup_complete()) {
    echo $force
        ? "\n-- Running setup ---------------------------------------\n\n"
        : "\n-- Setup not complete - starting interactive setup -----\n\n";
    require_once __DIR__ . '/setup-buzz-oauth.php';
    $rc = setup_main([$argv[0]]);
    if ($rc !== 0) {
        fwrite(STDERR, "\nSetup did not complete.  Exiting.\n");
        exit(1);
    }
}

echo "\n-- Running the sample ----------------------------------\n";
// Run the sample in a separate PHP process so its fresh config is loaded cleanly.
$php = PHP_BINARY;
$sample = dirname(__DIR__) . '/sample.php';
passthru(escapeshellarg($php) . ' ' . escapeshellarg($sample), $code);
exit($code);
