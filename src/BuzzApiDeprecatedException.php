<?php

declare(strict_types=1);

namespace Agilix\BuzzApi;

/**
 * Thrown when Buzz refuses a request because it used something deprecated
 * (response code "ApiDeprecated", or "unauthorized_client" from the OAuth
 * token endpoint).
 *
 * Deprecated commands, the api.agilixbuzz.com endpoint and password (Login3)
 * sessions for integration work keep working for existing users and domains,
 * but are refused for new ones.  The message is the server's own and says what
 * to use instead.  Never retry: the request is refused until the code is
 * changed.
 *
 * Extends BuzzApiException so existing handlers still catch it.
 */
final class BuzzApiDeprecatedException extends BuzzApiException
{
}
