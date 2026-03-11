<?php

declare(strict_types=1);

namespace Maatify\Crypto\Password\DTO;

use Maatify\Crypto\Password\Exception\InvalidArgonPolicyException;

final readonly class ArgonPolicyDTO
{
    public function __construct(
        public int $memoryCost,
        public int $timeCost,
        public int $threads
    ) {
        if ($memoryCost <= 0) {
            throw new InvalidArgonPolicyException('Argon memoryCost must be > 0');
        }

        if ($timeCost <= 0) {
            throw new InvalidArgonPolicyException('Argon timeCost must be > 0');
        }

        if ($threads <= 0) {
            throw new InvalidArgonPolicyException('Argon threads must be > 0');
        }
    }

    /**
     * @return array<string, int>
     */
    public function toNativeOptions(): array
    {
        return [
            'memory_cost' => $this->memoryCost,
            'time_cost'   => $this->timeCost,
            'threads'     => $this->threads,
        ];
    }
}
