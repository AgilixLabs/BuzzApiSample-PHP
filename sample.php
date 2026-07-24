<?php

declare(strict_types=1);

/**
 * Buzz API OAuth 2.0 sample — read-only demo.
 *
 * Demonstrates read-only access to the Buzz API:
 *   1. Configuring BuzzApiClient with OAuth credentials.
 *   2. Calling getuser2 to verify authentication and discover the home domain.
 *   3. Calling getdomain2 to read domain details.
 *
 * The sample is intentionally read-only — it can be run repeatedly without
 * modifying any data in the target domain.
 *
 * Quickest start:  php scripts/run-buzz-sample.php
 */

require_once __DIR__ . '/bootstrap.php';

use Agilix\BuzzApi\BuzzApiClient;

function main(): void
{
    $config = buzz_load_config();

    $userAgent = sprintf(
        'BuzzApiClient/1.0.0 (PHP; %s; %s)',
        $config['applicationInformation'],
        $config['contactInformation']
    );

    // Show INFO and above; DEBUG (request/response tracing) is suppressed for a clean demo.
    $logger = static function (string $level, string $message): void {
        if ($level === 'debug') {
            return;
        }
        fwrite(STDOUT, strtoupper($level) . ': ' . $message . "\n");
    };

    $client = BuzzApiClient::fromPemFile(
        $config['serverUrl'],
        $userAgent,
        $config['oauthUserId'],
        $config['oauthKid'],
        $config['privateKeyPath'],
        ['logger' => $logger]
    );

    run_sample($client);
}

function run_sample(BuzzApiClient $client): void
{
    echo "\n";
    echo "========================================================\n";
    echo "  Buzz API OAuth 2.0 Sample - Read-Only Demo (PHP)\n";
    echo "========================================================\n\n";

    // getuser2: verify authentication and discover the home domain.
    echo "-- getuser2 (verify authentication) --------------------\n";
    $userNode = $client->verifyResponse($client->jsonRequest('GET', 'getuser2'));
    $user = $userNode['user'] ?? [];

    // This server returns the identifier as "id"; older servers use "userid".
    $userId = $user['userid'] ?? ($user['id'] ?? null);
    printf("Authenticated as user %s (\"%s %s\", userid: %s)\n",
        $user['username'] ?? '', $user['firstname'] ?? '', $user['lastname'] ?? '', $userId ?? '');
    $domainId = $user['domainid'] ?? null;
    printf("Home domain: %s\n", $domainId ?? '');

    // getdomain2: read details about the account's home domain.
    if (!empty($domainId)) {
        echo "\n-- getdomain2 (read domain details) --------------------\n";
        $domainNode = $client->verifyResponse(
            $client->jsonRequest('GET', 'getdomain2', ['domainid' => $domainId])
        );
        $domain = $domainNode['domain'] ?? [];
        printf("Domain name: %s\n", $domain['name'] ?? '');
        printf("Userspace  : %s\n", $domain['userspace'] ?? '');
        if (!empty($domain['type'])) {
            printf("Type       : %s\n", $domain['type']);
        }
    }

    echo "\n========================================================\n";
    echo "  All API calls succeeded.  OAuth integration is working.\n";
    echo "  No data was created or modified.\n";
    echo "========================================================\n\n";
}

main();
