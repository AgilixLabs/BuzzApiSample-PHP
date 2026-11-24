<?php

declare(strict_types=1);

/**
 * Entry point for the Buzz API sample.
 *
 * If setup has not been completed (buzz-config.php missing or the private key
 * file not readable), the interactive setup runs first.  Then the read-only
 * sample runs, under a temporary application name (see below).
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
// It runs under a temporary application name, defined by a file PHP prepends to sample.php
// (auto_prepend_file), so the quick start works before you have named your application there.
// The file exists only in the temp directory for this run; sample.php is never edited.  Set
// your own name in sample.php before using the code anywhere else.
$quickStartName = 'QuickStartSample/1.0';
$php = PHP_BINARY;
$sample = dirname(__DIR__) . '/sample.php';
$prepend = tempnam(sys_get_temp_dir(), 'sample-quickstart-');
if ($prepend === false) {
    fwrite(STDERR, "Could not create a temporary file.\n");
    exit(1);
}
try {
    file_put_contents($prepend, "<?php\nconst YOUR_APPLICATION_NAME = " . var_export($quickStartName, true) . ";\n");
    passthru(
        escapeshellarg($php) . ' -d ' . escapeshellarg('auto_prepend_file=' . $prepend) . ' ' . escapeshellarg($sample),
        $code
    );
} finally {
    @unlink($prepend);
}
exit($code);
