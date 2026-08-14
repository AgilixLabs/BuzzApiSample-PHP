<?php

// Buzz API sample configuration.
// Copy this file to "buzz-config.php" and fill in the values, or run:
//     php scripts/run-buzz-sample.php
// which generates "buzz-config.php" for you.
//
// "buzz-config.php" is gitignored — never commit it.

return [
    // Buzz API server URL (no trailing slash).
    'serverUrl' => 'https://backgroundapi.agilixbuzz.com',

    // Included in the User-Agent header so Agilix support can identify your integration.
    'contactInformation' => '+https://example.com/; admin@example.com',
    'applicationInformation' => 'MyApp',

    // The userid of the Application Identity account (the OAuth client_id).
    'oauthUserId' => '12345678',

    // The key id (kid) chosen when the public key was registered with Buzz.
    'oauthKid' => '2025-q2',

    // Path to the RSA private key (PEM).  Keep this file secret; never commit it.
    'privateKeyPath' => 'private_key.pem',
];
