<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation;

use Maatify\Crypto\KeyRotation\Exceptions\KeyNotFoundException;

/**
 * KeyProviderInterface
 *
 * Contract for key storage and lifecycle mutation.
 *
 * Responsibilities:
 * - Provide access to keys
 * - Track key status
 * - Perform state transitions (e.g. promote active key)
 *
 * Providers MAY be:
 * - In-memory
 * - Database-backed
 * - External (Vault, KMS)
 */
interface KeyProviderInterface
{
    /**
     * Return all known keys.
     *
     * @return iterable<CryptoKeyInterface>
     */
    public function all(): iterable;

    /**
     * Return the currently ACTIVE key.
     *
     * @throws KeyNotFoundException If no active key exists
     */
    public function active(): CryptoKeyInterface;

    /**
     * Find a key by its immutable key_id.
     *
     * @throws KeyNotFoundException
     */
    public function find(string $keyId): CryptoKeyInterface;

    /**
     * Promote the given key to ACTIVE.
     *
     * Rules (enforced by provider):
     * - The target key MUST exist
     * - The target key becomes ACTIVE
     * - The previously ACTIVE key becomes INACTIVE
     *
     * @throws KeyNotFoundException
     */
    public function promote(string $keyId): void;
}
