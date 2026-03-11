<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation\DTO;

/**
 * KeyRotationDecisionDTO
 *
 * Represents the outcome of a rotation decision.
 *
 * POLICY OUTPUT ONLY — does NOT mutate anything.
 */
final readonly class KeyRotationDecisionDTO
{
    /**
     * @param   string  $newActiveKeyId
     * @param   string  $previousActiveKeyId
     * @param   bool    $rotationOccurred
     */
    public function __construct(
        public string $newActiveKeyId,
        public string $previousActiveKeyId,
        public bool $rotationOccurred
    ) {
    }
}
