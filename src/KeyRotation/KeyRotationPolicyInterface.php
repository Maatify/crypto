<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation;

use RuntimeException;

/**
 * KeyRotationPolicyInterface
 *
 * Defines how key rotation decisions are enforced.
 *
 * This interface:
 * - Enforces lifecycle rules
 * - Prevents invalid transitions
 * - Guarantees exactly one active key
 *
 * It does NOT:
 * - Store keys
 * - Perform crypto
 */
interface KeyRotationPolicyInterface
{
    /**
     * Validate provider state before usage.
     *
     * @throws RuntimeException if policy invariants are violated
     */
    public function validate(KeyProviderInterface $provider): void;

    /**
     * Resolve key for encryption.
     *
     * @throws RuntimeException if no active key is available
     */
    public function encryptionKey(KeyProviderInterface $provider): CryptoKeyInterface;

    /**
     * Resolve key for decryption by key_id.
     *
     * @throws RuntimeException if key is invalid or not allowed
     */
    public function decryptionKey(
        KeyProviderInterface $provider,
        string $keyId
    ): CryptoKeyInterface;
}
