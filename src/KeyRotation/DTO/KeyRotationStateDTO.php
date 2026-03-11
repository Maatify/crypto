<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation\DTO;

use Maatify\Crypto\KeyRotation\CryptoKeyInterface;

/**
 * KeyRotationStateDTO
 *
 * Snapshot of the key rotation state at a given point in time.
 *
 * Used for:
 * - Validation
 * - Auditing
 * - Debugging
 *
 * Contains NO logic.
 */
final readonly class KeyRotationStateDTO
{
    /**
     * @param   CryptoKeyInterface        $activeKey
     * @param   list<CryptoKeyInterface>  $inactiveKeys
     * @param   list<CryptoKeyInterface>  $retiredKeys
     */
    public function __construct(
        public CryptoKeyInterface $activeKey,
        public array $inactiveKeys,
        public array $retiredKeys
    ) {
    }
}
