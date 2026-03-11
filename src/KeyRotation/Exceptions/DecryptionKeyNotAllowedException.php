<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation\Exceptions;

/**
 * DecryptionKeyNotAllowedException
 *
 * Thrown when a key exists but is not permitted for decryption
 * under the current policy.
 */
final class DecryptionKeyNotAllowedException extends KeyRotationException
{
}
