<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\Password;

use Maatify\Crypto\Password\DTO\ArgonPolicyDTO;
use Maatify\Crypto\Password\Exception\PepperUnavailableException;
use Maatify\Crypto\Password\PasswordHasher;
use Maatify\Crypto\Password\Pepper\PasswordPepperProviderInterface;
use PHPUnit\Framework\TestCase;

class PasswordHasherTest extends TestCase
{
    private PasswordHasher $hasher;
    private PasswordPepperProviderInterface $pepperProvider;

    protected function setUp(): void
    {
        $this->pepperProvider = new class implements PasswordPepperProviderInterface {
            public function getPepper(): string
            {
                return 'test-global-pepper-secret-32bytes!';
            }
        };

        // Minimum safe argon cost for test speed
        $policy = new ArgonPolicyDTO(memoryCost: 1024, timeCost: 1, threads: 1);

        $this->hasher = new PasswordHasher($this->pepperProvider, $policy);
    }

    public function testHashGeneratesValidArgon2idHash(): void
    {
        $hash = $this->hasher->hash('my-secure-password');

        $this->assertStringStartsWith('$argon2id$', $hash);
        $this->assertTrue($this->hasher->verify('my-secure-password', $hash));
    }

    public function testVerifyFailsOnIncorrectPassword(): void
    {
        $hash = $this->hasher->hash('my-secure-password');

        $this->assertFalse($this->hasher->verify('wrong-password', $hash));
    }

    public function testNeedsRehashReturnsFalseForCurrentPolicy(): void
    {
        $hash = $this->hasher->hash('my-secure-password');

        $this->assertFalse($this->hasher->needsRehash($hash));
    }

    public function testNeedsRehashReturnsTrueForOldPolicy(): void
    {
        $oldPolicy = new ArgonPolicyDTO(memoryCost: 1024, timeCost: 1, threads: 1);
        $oldHasher = new PasswordHasher($this->pepperProvider, $oldPolicy);
        $hash = $oldHasher->hash('password');

        $newPolicy = new ArgonPolicyDTO(memoryCost: 2048, timeCost: 2, threads: 2);
        $newHasher = new PasswordHasher($this->pepperProvider, $newPolicy);

        $this->assertTrue($newHasher->needsRehash($hash));
    }

    public function testHashThrowsExceptionIfPepperIsEmpty(): void
    {
        $emptyPepperProvider = new class implements PasswordPepperProviderInterface {
            public function getPepper(): string
            {
                return '';
            }
        };

        $hasher = new PasswordHasher($emptyPepperProvider, new ArgonPolicyDTO(1024, 1, 1));

        $this->expectException(PepperUnavailableException::class);
        $hasher->hash('password');
    }

    public function testVerifyThrowsExceptionIfPepperIsEmpty(): void
    {
        $emptyPepperProvider = new class implements PasswordPepperProviderInterface {
            public function getPepper(): string
            {
                return '';
            }
        };

        $hasher = new PasswordHasher($emptyPepperProvider, new ArgonPolicyDTO(1024, 1, 1));

        $this->expectException(PepperUnavailableException::class);
        $hasher->verify('password', '$argon2id$v=19$m=1024,t=1,p=1$...');
    }
}
