<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\Integration;

use Maatify\Crypto\Password\DTO\ArgonPolicyDTO;
use Maatify\Crypto\Password\PasswordHasher;
use Maatify\Crypto\Password\Pepper\PasswordPepperProviderInterface;
use PHPUnit\Framework\TestCase;

class PasswordPipelineTest extends TestCase
{
    public function testEndToEndPasswordHashingAndVerification(): void
    {
        $pepperProvider = new class implements PasswordPepperProviderInterface {
            public function getPepper(): string
            {
                return 'integration-pepper-secret!';
            }
        };

        // Low cost policy for fast tests
        $policy = new ArgonPolicyDTO(memoryCost: 1024, timeCost: 1, threads: 1);
        $hasher = new PasswordHasher($pepperProvider, $policy);

        $plaintext = 'user-password-123';

        $hash = $hasher->hash($plaintext);

        $this->assertStringStartsWith('$argon2id$', $hash);

        $this->assertTrue($hasher->verify($plaintext, $hash));
        $this->assertFalse($hasher->verify('wrong-password', $hash));
    }
}
