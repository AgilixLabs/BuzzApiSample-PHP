<?php

declare(strict_types=1);

/**
 * Remove all artifacts created by setup-buzz-oauth.php.
 *
 *   1. Read buzz-config.php to find the OAuth account details.
 *   2. Log in as a Buzz admin (supports MFA).
 *   3. Delete the registered OAuth public key from Buzz.
 *   4. Delete the Application Identity account from Buzz.
 *   5. Delete the local key files and buzz-config.php.
 *
 * Usage:
 *     php scripts/cleanup-buzz-sample.php [--yes]
 *
 *     --yes   Skip the confirmation prompt (useful for automated cleanup).
 */

require_once __DIR__ . '/common.php';

function cleanup_main(array $argv): int
{
    $yes = in_array('--yes', $argv, true) || in_array('-y', $argv, true);

    if (!is_file(BUZZ_CONFIG_FILE)) {
        echo "buzz-config.php not found — nothing to clean up.\n";
        return 0;
    }
    $config = require BUZZ_CONFIG_FILE;
    if (!is_array($config)) {
        fwrite(STDERR, "buzz-config.php did not return an array.\n");
        return 1;
    }

    $server = rtrim((string) ($config['serverUrl'] ?? ''), '/');
    $oauthUserId = (string) ($config['oauthUserId'] ?? '');
    $oauthKid = (string) ($config['oauthKid'] ?? '');
    $privateKeyPath = (string) ($config['privateKeyPath'] ?? '');

    if ($server === '' || $oauthUserId === '') {
        fwrite(STDERR, "buzz-config.php is missing required fields (serverUrl, oauthUserId).\n");
        return 1;
    }

    echo "\n========================================================\n";
    echo "  Buzz API Sample - Cleanup\n";
    echo "========================================================\n\n";
    echo "This will:\n";
    echo "  * Delete OAuth public key (kid: {$oauthKid}) from Buzz\n";
    echo "  * Delete Application Identity account (userid: {$oauthUserId}) from Buzz\n";
    if ($privateKeyPath !== '') {
        echo "  * Delete local key files near: {$privateKeyPath}\n";
    }
    echo "  * Delete buzz-config.php\n";
    if (!$yes && !confirm("\nThis action is irreversible.  Continue?")) {
        echo "Aborted.\n";
        return 0;
    }

    echo "\n-- Admin login -----------------------------------------\n";
    $adminToken = admin_login($server);

    if ($oauthKid !== '') {
        echo "\n-- Deleting OAuth key (kid: {$oauthKid}) ----------------\n";
        [$status] = delete_public_key($server, $oauthUserId, $oauthKid, $adminToken);
        if ($status === 200 || $status === 204) {
            echo "OAuth key deleted (HTTP {$status}).\n";
        } elseif ($status === 404) {
            echo "OAuth key not found (already deleted or never registered).\n";
        } else {
            fwrite(STDERR, "Warning: HTTP {$status} deleting key. Continuing.\n");
        }
    }

    echo "\n-- Deleting Application Identity account (userid: {$oauthUserId}) --\n";
    $resp = buzz_post($server, 'deleteusers', ['requests' => ['user' => [['userid' => $oauthUserId]]]], $adminToken);
    // The per-user outcome is authoritative.  The OUTER code is OK whenever the request
    // was merely well formed, so checking it first would report success for a delete
    // that was actually denied or whose target did not exist.
    $delItem = item_result($resp);
    $delCode = $delItem['code'] !== '' ? $delItem['code'] : response_code($resp);
    $delDetail = $delItem['message'] !== '' ? " - {$delItem['message']}" : '';
    if ($delCode === 'OK') {
        echo "Application Identity account deleted.\n";
    } else {
        fwrite(STDERR, 'Warning: delete returned code "' . $delCode . '"' . $delDetail . ". Continuing.\n");
    }

    echo "\n-- Removing local files --------------------------------\n";
    $keyDir = $privateKeyPath !== '' ? dirname($privateKeyPath) : dirname(__DIR__);
    foreach (['private_key.pem', 'public_key.pem'] as $name) {
        remove_file($keyDir . DIRECTORY_SEPARATOR . $name);
    }
    if ($privateKeyPath !== '') {
        remove_file($privateKeyPath);
    }
    remove_file(BUZZ_CONFIG_FILE);

    echo "\n========================================================\n";
    echo "  Cleanup complete.  Environment is back to a clean state.\n";
    echo "========================================================\n\n";
    return 0;
}

function remove_file(string $path): void
{
    if ($path !== '' && is_file($path)) {
        if (@unlink($path)) {
            echo "Removed: {$path}\n";
        } else {
            fwrite(STDERR, "Warning: could not remove {$path}\n");
        }
    }
}

if (realpath($argv[0] ?? '') === realpath(__FILE__)) {
    exit(cleanup_main($argv));
}
