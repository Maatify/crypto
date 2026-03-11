<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests;

use Maatify\Crypto\Password\DTO\ArgonPolicyDTO;
use Maatify\Crypto\Password\PasswordHasher;
use Maatify\Crypto\Password\Pepper\PasswordPepperProviderInterface;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    public function testPasswordHashAndVerify(): void
    {
        $pepperProvider = new class implements PasswordPepperProviderInterface {
            public function getPepper(): string
            {
                return 'test-pepper';
            }
        };

        $policy = new ArgonPolicyDTO(
            memoryCost: PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            timeCost: PASSWORD_ARGON2_DEFAULT_TIME_COST,
            threads: PASSWORD_ARGON2_DEFAULT_THREADS
        );

        $hasher = new PasswordHasher($pepperProvider, $policy);

        $password = 'super-secret-password';

        $hash = $hasher->hash($password);

        $this->assertTrue(
            $hasher->verify($password, $hash)
        );
    }
}
