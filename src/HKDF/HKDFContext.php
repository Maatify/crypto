<?php

declare(strict_types=1);

namespace Maatify\Crypto\HKDF;

use Maatify\Crypto\HKDF\Exceptions\InvalidContextException;

final class HKDFContext
{
    private string $value;

    public function __construct(string $value)
    {
        $value = trim($value);

        if ($value === '') {
            throw new InvalidContextException('HKDF context must not be empty.');
        }

        if (! str_contains($value, ':v')) {
            throw new InvalidContextException('HKDF context must be versioned (e.g. "email:payload:v1").');
        }

        if (strlen($value) > 255) {
            throw new InvalidContextException('HKDF context is too long.');
        }

        $this->value = $value;
    }

    public function value(): string
    {
        return $this->value;
    }
}
