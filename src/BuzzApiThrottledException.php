<?php

declare(strict_types=1);

namespace Agilix\BuzzApi;

/**
 * Thrown when the Buzz API throttles a request (rate limit, time limit, or
 * backend pressure) and the client has run out of retries, or when items
 * within a batch or multi-object request were throttled.
 *
 * Extends BuzzApiException so existing handlers still catch it.
 * getStatusCode() is 429 or 503 even when the server wrapped the throttle in
 * HTTP 200.
 */
final class BuzzApiThrottledException extends BuzzApiException
{
    /** @var string|null */
    private $throttleCode;
    /** @var float|null seconds */
    private $retryAfter;
    /** @var int[] */
    private $throttledItemIndexes;
    /** @var array|null */
    private $response;

    /**
     * @param string      $message
     * @param string|null $throttleCode         Envelope code (or OAuth error code), if the server sent one.
     * @param array|null  $response             The full decoded response envelope.
     * @param int[]       $throttledItemIndexes Indexes of throttled batch/multi-object items; empty for a whole-request throttle.
     * @param float|null  $retryAfter           Seconds the server asked the client to wait, if it said.
     * @param int         $statusCode           429 or 503.
     */
    public function __construct(
        string $message,
        ?string $throttleCode,
        ?array $response,
        array $throttledItemIndexes = [],
        ?float $retryAfter = null,
        int $statusCode = 429
    ) {
        parent::__construct($message, $statusCode);
        $this->throttleCode = $throttleCode;
        $this->response = $response;
        $this->throttledItemIndexes = $throttledItemIndexes;
        $this->retryAfter = $retryAfter;
    }

    /**
     * The throttle code from the response envelope (for example "TimeLimit",
     * "RateLimit", "BackendPressure", or "TooManyRequests"), or the OAuth error
     * code for the token endpoint.  Null if the server sent no code.
     */
    public function getThrottleCode(): ?string
    {
        return $this->throttleCode;
    }

    /** How long, in seconds, the server asked the client to wait (Retry-After or X-RateLimit-Reset), if it said. */
    public function getRetryAfter(): ?float
    {
        return $this->retryAfter;
    }

    /**
     * For batch and multi-object requests, the indexes of the items that were
     * throttled and should be resubmitted.  Items not listed completed normally
     * (or failed for other reasons) and should not be resubmitted.  Empty when
     * the whole request was throttled.
     *
     * @return int[]
     */
    public function getThrottledItemIndexes(): array
    {
        return $this->throttledItemIndexes;
    }

    /** The full response envelope, including the results of any items that were not throttled. */
    public function getResponse(): ?array
    {
        return $this->response;
    }
}
