<?php

declare(strict_types=1);

namespace Maatify\Crypto\DX;

use Maatify\Crypto\Reversible\ReversibleCryptoService;

/**
 * CryptoProvider
 *
 * Unified Developer Experience (DX) Facade for Cryptography.
 *
 * Provides a single injection point for:
 * 1. Context-based encryption (HKDF Pipeline)
 * 2. Direct encryption (No-HKDF Pipeline)
 *
 * The recommended default for application-level encryption is `context()`.
 * It enforces HKDF-based domain separation.
 *
 * @internal This is a DX helper.
 */
final readonly class CryptoProvider
{
    public function __construct(
        private CryptoContextFactory $contextFactory,
        private CryptoDirectFactory $directFactory
    ) {
    }

    /**
     * Get a crypto service bound to a specific context.
     *
     * Uses HKDF to derive domain-separated encryption keys
     * from the root rotation keys.
     *
     * Pipeline:
     * KeyRotation -> HKDF -> ReversibleCrypto
     *
     * Example contexts:
     * - "user:email:v1"
     * - "auth:session:v1"
     * - "payment:card:v1"
     *
     * @param string $context Explicit context string (must be versioned)
     * @return ReversibleCryptoService
     */
    public function context(string $context): ReversibleCryptoService
    {
        return $this->contextFactory->create($context);
    }

    /**
     * Get a crypto service using raw root keys directly.
     *
     * ⚠ WARNING:
     * This pipeline bypasses HKDF domain separation.
     *
     * Without domain separation, the same root key may be reused
     * across different encryption domains, which increases the
     * blast radius if a key is ever compromised.
     *
     * Prefer `context()` for application data encryption.
     *
     * Only use `direct()` when encrypting:
     * - internal system secrets
     * - infrastructure-level data
     * - environments where domain separation is not required
     *
     * Pipeline:
     * KeyRotation -> ReversibleCrypto
     *
     * @warning This method intentionally bypasses HKDF domain separation.
     *
     * @return ReversibleCryptoService
     */
    public function direct(): ReversibleCryptoService
    {
        return $this->directFactory->create();
    }
}
