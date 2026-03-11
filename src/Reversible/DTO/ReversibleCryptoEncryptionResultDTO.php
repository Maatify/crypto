<?php

declare(strict_types=1);

namespace Maatify\Crypto\Reversible\DTO;

/**
 * ReversibleCryptoEncryptionResult
 *
 * Value object representing the result of a reversible encryption operation.
 *
 * This object contains ONLY the cryptographic output.
 * It does NOT know anything about:
 * - storage
 * - databases
 * - key identifiers
 * - algorithms
 *
 * All fields are immutable and explicitly defined.
 */
final readonly class ReversibleCryptoEncryptionResultDTO
{
    /**
     * @param   string       $cipher  Encrypted binary data
     * @param   string|null  $iv      Initialization Vector (if required by algorithm)
     * @param   string|null  $tag     Authentication Tag (if required by algorithm)
     */
    public function __construct(
        public string $cipher,
        public ?string $iv,
        public ?string $tag
    ) {
    }
}
