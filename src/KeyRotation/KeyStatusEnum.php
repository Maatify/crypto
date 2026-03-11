<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation;

/**
 * KeyStatusEnum
 *
 * Defines the lifecycle state of a cryptographic key.
 *
 * IMPORTANT:
 * - This enum is POLICY ONLY.
 * - It has NO cryptographic meaning.
 */
enum KeyStatusEnum: string
{
    /**
     * Active key.
     * - Used for encryption
     * - Used for decryption
     */
    case ACTIVE = 'active';

    /**
     * Inactive key.
     * - NOT used for encryption
     * - Allowed for decryption
     */
    case INACTIVE = 'inactive';

    /**
     * Retired key.
     * - NOT used for encryption
     * - Allowed for decryption (legacy only)
     */
    case RETIRED = 'retired';

    /**
     * Whether encryption is allowed with this key.
     */
    public function canEncrypt(): bool
    {
        return $this === self::ACTIVE;
    }

    /**
     * Whether decryption is allowed with this key.
     */
    public function canDecrypt(): bool
    {
        return true;
    }
}
