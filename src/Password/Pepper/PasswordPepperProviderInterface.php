<?php

declare(strict_types=1);

namespace Maatify\Crypto\Password\Pepper;

use Maatify\Crypto\Password\Exception\PepperUnavailableException;

interface PasswordPepperProviderInterface
{
    /**
     * @throws PepperUnavailableException when pepper is unavailable
     */
    public function getPepper(): string;
}
