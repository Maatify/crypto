<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\Reversible;

use Maatify\Crypto\Reversible\Algorithms\Aes256GcmAlgorithm;
use Maatify\Crypto\Reversible\Exceptions\CryptoAlgorithmNotSupportedException;
use Maatify\Crypto\Reversible\Registry\ReversibleCryptoAlgorithmRegistry;
use Maatify\Crypto\Reversible\ReversibleCryptoAlgorithmEnum;
use PHPUnit\Framework\TestCase;

class ReversibleCryptoAlgorithmRegistryTest extends TestCase
{
    private ReversibleCryptoAlgorithmRegistry $registry;

    protected function setUp(): void
    {
        $this->registry = new ReversibleCryptoAlgorithmRegistry();
    }

    public function testCanRegisterAndRetrieveAlgorithm(): void
    {
        $algorithm = new Aes256GcmAlgorithm();

        $this->assertFalse($this->registry->has(ReversibleCryptoAlgorithmEnum::AES_256_GCM));
        $this->registry->register($algorithm);

        $this->assertTrue($this->registry->has(ReversibleCryptoAlgorithmEnum::AES_256_GCM));

        $retrieved = $this->registry->get(ReversibleCryptoAlgorithmEnum::AES_256_GCM);
        $this->assertSame($algorithm, $retrieved);

        $this->assertContains(ReversibleCryptoAlgorithmEnum::AES_256_GCM->value, $this->registry->list());
    }

    public function testRegisterThrowsExceptionIfAlreadyRegistered(): void
    {
        $algorithm = new Aes256GcmAlgorithm();
        $this->registry->register($algorithm);

        $this->expectException(CryptoAlgorithmNotSupportedException::class);
        $this->expectExceptionMessage('Crypto algorithm already registered: aes-256-gcm');
        $this->registry->register($algorithm);
    }

    public function testGetThrowsExceptionIfAlgorithmNotRegistered(): void
    {
        $this->expectException(CryptoAlgorithmNotSupportedException::class);
        $this->expectExceptionMessage('Unsupported crypto algorithm: aes-256-gcm');
        $this->registry->get(ReversibleCryptoAlgorithmEnum::AES_256_GCM);
    }

    public function testListReturnsEmptyArrayWhenEmpty(): void
    {
        $this->assertEmpty($this->registry->list());
    }
}
