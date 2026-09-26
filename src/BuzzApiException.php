<?php

declare(strict_types=1);

namespace Agilix\BuzzApi;

/**
 * Thrown when a Buzz API call fails or returns a non-OK response code.
 *
 * When the failure came from an HTTP error status, getStatusCode() returns it
 * (it is also the exception code).  See BuzzApiThrottledException for throttles.
 */
class BuzzApiException extends \RuntimeException
{
    /** @var int|null */
    private $statusCode;

    /**
     * @param string          $message
     * @param int|null        $statusCode HTTP status of the failed response, if there was one.
     * @param \Throwable|null $previous
     */
    public function __construct(string $message = '', ?int $statusCode = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, $statusCode ?? 0, $previous);
        $this->statusCode = $statusCode;
    }

    /** The HTTP status of the failed response, or null if the failure was not an HTTP error. */
    public function getStatusCode(): ?int
    {
        return $this->statusCode;
    }
}
