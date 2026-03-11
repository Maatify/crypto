<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation;

use DateTimeImmutable;

/**
 * CryptoKeyInterface
 *
 * Immutable representation of a cryptographic key.
 *
 * IMPORTANT:
 * - This interface does NOT expose how the key is stored.
 * - It does NOT perform cryptographic operations.
 * - It represents key identity + policy metadata only.
 */
interface CryptoKeyInterface
{
    /**
     * Immutable key identifier.
     */
    public function id(): string;

    /**
     * Raw binary key material.
     *
     * WARNING:
     * - MUST be handled carefully
     * - MUST NOT be logged
     */
    public function material(): string;

    /**
     * Current lifecycle status of the key.
     */
    public function status(): KeyStatusEnum;

    /**
     * Creation timestamp (for audit / ordering).
     */
    public function createdAt(): DateTimeImmutable;

    /**
     * Return a NEW key instance with a different status.
     *
     * This is required to keep keys immutable while still allowing
     * providers to perform lifecycle transitions.
     */
    public function withStatus(KeyStatusEnum $status): self;
}
