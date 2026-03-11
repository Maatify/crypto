<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation\DTO;

/**
 * KeyRotationValidationResultDTO
 *
 * Result object for validating key provider state.
 *
 * Explicit, readable, and audit-friendly.
 */
final readonly class KeyRotationValidationResultDTO
{
    public function __construct(
        public bool $isValid,
        public ?string $errorMessage = null
    ) {
    }
}
