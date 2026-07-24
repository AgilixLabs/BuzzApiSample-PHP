# BuzzApiSample-PHP

A PHP sample and reusable client library for the Buzz API. The `BuzzApiClient` class handles
OAuth 2.0 authentication, automatic token refresh, exponential backoff, and rate-limit
compliance so your integration code can focus on business logic.

Targets **PHP 7.4+** for broad compatibility. Uses only the bundled `openssl`, `curl`, and
`json` extensions — **no Composer dependencies**.

## Authentication

The only authentication method supported by the client is **OAuth 2.0 JWT Client Credentials**
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) +
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)).
An RSA private key signs a short-lived JWT assertion; Buzz verifies the signature against the
registered public key and returns a Bearer access token valid for one hour. The private key
never leaves your system — there is no shared secret to intercept.

> The legacy username/password (`login3`) flow is **not** used by new integrations and is not
> part of this client. It appears only inside the setup/cleanup scripts, where an administrator
> must briefly authenticate to create the Application Identity account and register keys.

---

## Overview

**sample.php** demonstrates read-only access:
1. Configuring `BuzzApiClient` with OAuth credentials and a Buzz server URL.
2. Calling `getuser2` to verify authentication and discover the home domain.
3. Calling `getdomain2` to read domain details.

The sample is intentionally read-only — it can be run repeatedly without modifying any data.

**BuzzApiClient** simplifies integration by:
- Managing OAuth tokens automatically — requesting and refreshing Bearer tokens as needed.
- Retrying transient failures with exponential backoff (1 s → 64 s, up to 5 retries).
- Honouring `Retry-After` and `X-RateLimit-Reset` headers from the server.
- Providing `jsonRequest` and `verifyResponse` helpers for common JSON API patterns.

---

## Requirements

- PHP 7.4 or newer with the `openssl`, `curl`, and `json` extensions (all bundled with standard
  PHP builds).
- Optionally [Composer](https://getcomposer.org/) — running `composer install` generates the PSR-4
  autoloader, but the sample also works without it (a built-in fallback autoloader is used).

```bash
composer install    # optional
```

> **Windows note:** PHP on Windows ships without a CA bundle, so HTTPS calls can fail with
> `curl error 60: SSL certificate problem`. Download [cacert.pem](https://curl.se/ca/cacert.pem)
> and set `curl.cainfo` and `openssl.cafile` in your `php.ini` to its path. Linux and macOS use
> the system CA store and need no configuration.

## Compatibility

Written for **PHP 7.4** for broad reach (it is still common on shared hosting), and verified to
run unchanged on every major version through the current release (**7.4 – 8.5**), with no
deprecation notices on PHP 8.5. The code avoids PHP-8-removed behavior, and `composer.json`
requires only `php: >=7.4` (no upper bound), so the newest PHP works without changes. Nothing
here discourages running on the latest PHP.

## Configuration

Configuration uses a **PHP config file** — the canonical plain-PHP convention. Copy
`buzz-config.example.php` to `buzz-config.php` (gitignored) and fill it in, or let the setup
script generate it. The file returns an associative array:

```php
<?php
return [
    'serverUrl'              => 'https://api.agilixbuzz.com',
    'contactInformation'     => '+https://example.com/; admin@example.com',
    'applicationInformation' => 'MyApp',
    'oauthUserId'            => '12345678',
    'oauthKid'               => '2025-q2',
    'privateKeyPath'         => 'private_key.pem',
];
```

---

## Quickest start

### Run (setup + demo in one command)

The run script checks whether one-time setup has been completed. If not, it runs the interactive
setup first, then executes the read-only demo.

```bash
php scripts/run-buzz-sample.php
php scripts/run-buzz-sample.php --setup    # force re-running setup
```

### Cleanup (return to a clean state)

Deletes the Application Identity account from Buzz, removes the registered OAuth key, and deletes
the local key files and `buzz-config.php`.

```bash
php scripts/cleanup-buzz-sample.php
```

---

## OAuth setup (one time per application)

The setup script automates all of the following, but you can also perform the steps manually.

### Step 1 — Create an Application Identity account

An Application Identity account authenticates exclusively via OAuth. Create it with the
`createusers2` API and `type=applicationidentity`, using an admin account with the Create User
right in the target domain. Record the returned `userid` — this is your **OAuth User ID**
(`oauthUserId`), used as the OAuth `client_id`.

### Step 2 — Generate an RSA key pair

```bash
php scripts/new-buzz-oauth-key.php                 # writes private_key.pem + public_key.pem
php scripts/new-buzz-oauth-key.php --out secrets --bits 4096
```

Choose a **Key ID** (`kid`), e.g. `2025-q2`. Allowed characters: ASCII letters, digits, `-`, `_`,
`.` (max 128).

> **SECURITY** — `private_key.pem` is gitignored. Store it in a secrets manager for production.
> Never commit it.

### Step 3 — Register the public key with Buzz

```bash
php scripts/register-buzz-oauth-key.php \
    -s https://api.agilixbuzz.com \
    -u 12345678 \
    -k 2025-q2 \
    -p public_key.pem
# Admin Bearer token via -t, the BUZZ_ADMIN_TOKEN env var, or an interactive prompt.
```

A `204 No Content` response means the key is stored.

### Step 4 — Configure and run

Create `buzz-config.php` (see Configuration above) or run `php scripts/run-buzz-sample.php`, then:

```bash
php sample.php
```

---

## Using BuzzApiClient in your own code

```php
require __DIR__ . '/bootstrap.php';   // or vendor/autoload.php

use Agilix\BuzzApi\BuzzApiClient;

$client = BuzzApiClient::fromPemFile(
    'https://api.agilixbuzz.com',
    'MyApp/1.0 (PHP; MyApp; admin@example.com)',
    '12345678',        // oauthUserId
    '2025-q2',         // oauthKid
    'private_key.pem'  // privateKeyPath
);

// BuzzApiClient obtains and refreshes Bearer tokens automatically.
$user   = $client->verifyResponse($client->jsonRequest('GET', 'getuser2'));
$domain = $client->verifyResponse($client->jsonRequest('GET', 'getdomain2', ['domainid' => '6']));
```

`jsonRequest($method, $cmd, $params, $jsonBody, $includeToken)` returns the decoded JSON response.
`verifyResponse($node)` throws `Agilix\BuzzApi\BuzzApiException` unless `response.code === "OK"`
(and recursively checks child responses from batch APIs).

---

## Key management

### Rotating a key (zero downtime)

1. Generate a new key pair and choose a new `kid`.
2. Register the new public key (PUTting a new `kid` leaves the old key active).
3. Update `oauthKid` and `privateKeyPath` to the new key.
4. Once all instances have switched over, delete the old key:
   `DELETE {server}/api/users/{userid}/keys/{old-kid}` with an admin Bearer token.

### Revoking a compromised key

Register a new key, switch your app to it, then delete the compromised public key and revoke
outstanding tokens (`POST {server}/api/oauth/revoke` with form body `token=<access_token>`).

---

## Troubleshooting OAuth

| Error | Cause | Fix |
|-------|-------|-----|
| `invalid_client: The client_assertion JWT has expired.` | Clock skew or a slow retry. | Sync your system clock (NTP). A fresh JWT is built for every token request. |
| `invalid_client: No active key found for the specified 'kid'.` | `oauthKid` doesn't match a registered key. | Re-register the key and verify the `kid` matches exactly. |
| `invalid_client: ... signature or claims are invalid.` | Wrong private key, or `iss`/`sub` mismatch. | Confirm `oauthUserId` is the Application Identity account's `userid` and the key matches the registered public key. |
| HTTP 400 registering a key | Wrong PEM format or key too small. | Use an SPKI PEM (`-----BEGIN PUBLIC KEY-----`), minimum 2048 bits. |
| HTTP 401/403 registering a key | Admin token lacks Update User rights. | Use an admin with the Update User right on the account. |
