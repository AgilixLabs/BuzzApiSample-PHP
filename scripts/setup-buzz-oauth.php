<?php

declare(strict_types=1);

/**
 * Interactive guided setup for Buzz OAuth 2.0 authentication.
 *
 *   1. Prompt for the Buzz server URL.
 *   2. Log in as a Buzz administrator (supports MFA) to perform setup.
 *   3. Create (or reuse) an Application Identity account.
 *   4. Generate an RSA key pair (private key stored as a PEM file).
 *   5. Register the public key with Buzz.
 *   6. Write buzz-config.php so `php sample.php` works immediately.
 *
 * Usage:
 *     php scripts/setup-buzz-oauth.php [--server URL] [--bits N] [--key-dir DIR]
 *
 * Every prompt falls back to an environment variable (see common.php and the
 * BUZZ_SETUP_* variables) so the whole flow can run unattended.
 */

require_once __DIR__ . '/common.php';
require_once __DIR__ . '/new-buzz-oauth-key.php';

function setup_main(array $argv): int
{
    $server = '';
    $bits = 0;
    $keyDir = dirname(__DIR__);
    for ($i = 1; $i < count($argv); $i++) {
        switch ($argv[$i]) {
            case '-s': case '--server':  $server = $argv[++$i] ?? ''; break;
            case '-b': case '--bits':    $bits = (int) ($argv[++$i] ?? 0); break;
            case '--key-dir':            $keyDir = $argv[++$i] ?? $keyDir; break;
        }
    }

    echo "\n==========================================================\n";
    echo "  Buzz OAuth 2.0 Application Setup (PHP)\n";
    echo "==========================================================\n";

    out_section('Step 1: Buzz Server URL');
    if ($server === '') {
        $server = prompt_required('Buzz API server URL (e.g. https://api.agilixbuzz.com)', '', 'BUZZ_SERVER_URL');
    }
    $server = rtrim($server, '/');
    echo "  Server: {$server}\n";

    out_section('Step 2: Admin Login');
    echo "Log in as a Buzz administrator to perform the one-time setup.\n";
    echo "This session is used only during setup and is not stored anywhere.\n\n";
    $adminToken = admin_login($server);

    out_section('Step 3: Application Information');
    echo "Included in the User-Agent header so Agilix support can identify your integration.\n\n";
    $contact = prompt_required('Your contact info (name, email, or URL)', '', 'BUZZ_CONTACT_INFORMATION');
    $appName = prompt_required('Application name (e.g. SisSync)', '', 'BUZZ_APPLICATION_INFORMATION');

    out_section('Step 4: Application Identity Account');
    echo "This Buzz user represents your application.  It authenticates via OAuth only.\n\n";
    $oauthUserId = get_or_create_account($server, $adminToken);

    out_section('Step 5: RSA Key Generation');
    if ($bits === 0) {
        $envBits = (int) (getenv('BUZZ_SETUP_KEY_BITS') ?: 0);
        $bits = $envBits > 0 ? $envBits : (int) prompt_required('RSA key size in bits', '2048');
    }
    $kid = getenv('BUZZ_SETUP_KID') ?: prompt_required('Key id (kid) for this key', default_kid());
    if (!preg_match('/^[A-Za-z0-9._-]{1,128}$/', (string) $kid)) {
        fail("Invalid kid '{$kid}'. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.");
    }
    out_info("Kid : {$kid}");
    [$privPath, $pubPath] = generate_key_pair($keyDir, $bits, true);
    echo "  Private key: {$privPath}\n";

    out_section('Step 6: Registering Public Key with Buzz');
    out_info("PUT {$server}/api/users/{$oauthUserId}/keys/{$kid}");
    [$status, $body] = register_public_key($server, $oauthUserId, (string) $kid, (string) file_get_contents($pubPath), $adminToken);
    if ($status === 204) {
        echo " 204 OK\n";
    } else {
        fail("Key registration returned HTTP {$status}. {$body}");
    }

    out_section('Step 7: Writing Configuration');
    $path = buzz_write_config([
        'serverUrl' => $server,
        'contactInformation' => $contact,
        'applicationInformation' => $appName,
        'oauthUserId' => $oauthUserId,
        'oauthKid' => (string) $kid,
        'privateKeyPath' => $privPath,
    ]);
    echo "  Written: {$path}\n";

    echo "\n==========================================================\n";
    echo "  Setup complete!\n";
    echo "==========================================================\n";
    echo "OAuth User ID : {$oauthUserId}\n";
    echo "Key ID (kid)  : {$kid}\n";
    echo "Private key   : {$privPath}\n";
    echo "Config file   : {$path}\n";
    echo "\nTo test:  php sample.php\n\n";
    return 0;
}

function get_or_create_account(string $server, string $adminToken): string
{
    $createEnv = getenv('BUZZ_SETUP_CREATE_NEW');
    $doCreate = $createEnv !== false ? stripos((string) $createEnv, 'y') === 0
        : confirm('Create a new Application Identity account?', true);

    if (!$doCreate) {
        return prompt_required('Existing Application Identity account userid', '', 'BUZZ_SETUP_OAUTH_USER_ID');
    }

    $targetDomain = (string) (getenv('BUZZ_SETUP_DOMAINID') ?: '');
    if ($targetDomain === '') {
        echo 'Fetching available domains...';
        $domains = list_domains($server, $adminToken);
        if ($domains) {
            echo " done\n\n";
            foreach ($domains as $i => [$did, $name]) {
                printf("  %2d. %-30s (id: %s)\n", $i + 1, $name, $did);
            }
            $choice = prompt_required("\nEnter domain number or type the domainid directly");
            $targetDomain = (ctype_digit($choice) && (int) $choice >= 1 && (int) $choice <= count($domains))
                ? $domains[(int) $choice - 1][0] : $choice;
        } else {
            echo " (could not fetch domains)\n\n";
            $targetDomain = prompt_required('Domain id for the new account (e.g. //myschool or a numeric id)');
        }
    }

    $username = prompt_required('Username for the account (e.g. sis-sync)', '', 'BUZZ_SETUP_APP_USERNAME');
    $firstname = prompt_required('First name (e.g. SIS)', '', 'BUZZ_SETUP_APP_FIRSTNAME');
    $lastname = prompt_required('Last name (e.g. Sync)', '', 'BUZZ_SETUP_APP_LASTNAME');
    $email = prompt_optional('Email address', 'BUZZ_SETUP_APP_EMAIL');

    $user = ['domainid' => $targetDomain, 'type' => 'applicationidentity',
        'username' => $username, 'firstname' => $firstname, 'lastname' => $lastname];
    if ($email !== '') {
        $user['email'] = $email;
    }

    echo "\nCreating Application Identity account '{$username}'...";
    $resp = buzz_post($server, 'createusers2', ['requests' => ['user' => [$user]]], $adminToken);
    if (response_code($resp) !== 'OK') {
        fail('CreateUsers2 failed (code: ' . response_code($resp) . ').  Response: ' . json_encode($resp));
    }
    $userId = extract_created_userid($resp);
    if ($userId === '') {
        fail('CreateUsers2 succeeded but returned no userid.  Response: ' . json_encode($resp));
    }
    echo " OK (userid: {$userId})\n";
    return $userId;
}

/**
 * @return array<int,array{0:string,1:string}>
 */
function list_domains(string $server, string $token): array
{
    $resp = buzz_get($server, 'getdomains', [], $token);
    if (response_code($resp) !== 'OK') {
        return [];
    }
    $domains = $resp['response']['domains']['domain'] ?? [];
    if (isset($domains['id']) || isset($domains['name'])) {  // single object, not a list
        $domains = [$domains];
    }
    $result = [];
    foreach ($domains as $d) {
        if (is_array($d)) {
            $result[] = [(string) ($d['id'] ?? ($d['domainid'] ?? '')), (string) ($d['name'] ?? '')];
        }
    }
    return $result;
}

/**
 * @param array<string,mixed>|null $resp
 */
function extract_created_userid(?array $resp): string
{
    $r = (is_array($resp) && isset($resp['response'])) ? $resp['response'] : ($resp ?? []);
    $inner = $r['responses']['response'] ?? [];
    if (isset($inner[0])) {
        $inner = $inner[0];
    }
    $user = is_array($inner) ? ($inner['user'] ?? []) : [];
    return (string) ($user['userid'] ?? ($user['id'] ?? ''));
}

function default_kid(): string
{
    $year = (int) gmdate('Y');
    $q = (int) ((((int) gmdate('n')) + 2) / 3);
    return "{$year}-q{$q}";
}

if (realpath($argv[0] ?? '') === realpath(__FILE__)) {
    exit(setup_main($argv));
}
