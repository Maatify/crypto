<?php

declare(strict_types=1);

namespace Maatify\Crypto\Reversible\Exceptions;

use RuntimeException;

/**
 * CryptoKeyNotFoundException
 *
 * Thrown when a required encryption/decryption key
 * is missing or not available in the provided key set.
 *
 * This is a FAIL-CLOSED exception.
 */
final class CryptoKeyNotFoundException extends RuntimeException
{
}
