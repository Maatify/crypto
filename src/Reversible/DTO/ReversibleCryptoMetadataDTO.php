<?php

declare(strict_types=1);

namespace Maatify\Crypto\Reversible\DTO;

/**
 * ReversibleCryptoMetadata
 *
 * Metadata required to successfully decrypt reversible encrypted data.
 *
 * This object MUST match the algorithm requirements:
 * - IV must be present if required
 * - Tag must be present if required
 *
 * Validation of requirements is the responsibility of the algorithm implementation.
 */
final readonly class ReversibleCryptoMetadataDTO
{
    /**
     * @param   string|null  $iv   Initialization Vector
     * @param   string|null  $tag  Authentication Tag
     */
    public function __construct(
        public ?string $iv,
        public ?string $tag
    ) {
    }
}
