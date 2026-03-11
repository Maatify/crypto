<?php

declare(strict_types=1);

namespace Maatify\Crypto\Reversible\Exceptions;

use RuntimeException;

/**
 * CryptoDecryptionFailedException
 *
 * Thrown when reversible decryption fails due to:
 * - Invalid authentication tag
 * - Corrupted ciphertext
 * - Incorrect key
 * - Missing or invalid metadata (IV / Tag)
 *
 * This exception MUST always be treated as FAIL-CLOSED.
 */
final class CryptoDecryptionFailedException extends RuntimeException
{
}
