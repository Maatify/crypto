<?php

declare(strict_types=1);

namespace Maatify\Crypto\HKDF;

use Maatify\Crypto\HKDF\Exceptions\InvalidOutputLengthException;
use Maatify\Crypto\HKDF\Exceptions\InvalidRootKeyException;

final class HKDFPolicy
{
    public const MIN_ROOT_KEY_LENGTH = 32; // bytes
    public const MAX_OUTPUT_LENGTH   = 64; // bytes (SHA-256 limit)

    public static function assertValidRootKey(string $rootKey): void
    {
        if (strlen($rootKey) < self::MIN_ROOT_KEY_LENGTH) {
            throw new InvalidRootKeyException(
                'Root key length is insufficient for HKDF.'
            );
        }
    }

    public static function assertValidOutputLength(int $length): void
    {
        if ($length <= 0 || $length > self::MAX_OUTPUT_LENGTH) {
            throw new InvalidOutputLengthException(
                'Invalid HKDF output length requested.'
            );
        }
    }
}
