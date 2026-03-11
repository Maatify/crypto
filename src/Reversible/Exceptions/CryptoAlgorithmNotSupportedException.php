<?php

declare(strict_types=1);

namespace Maatify\Crypto\Reversible\Exceptions;

use RuntimeException;

/**
 * CryptoAlgorithmNotSupportedException
 *
 * Thrown when a reversible crypto algorithm is:
 * - Not registered
 * - Not allowed by the security whitelist
 *
 * This is a FAIL-CLOSED exception.
 */
final class CryptoAlgorithmNotSupportedException extends RuntimeException
{
}
