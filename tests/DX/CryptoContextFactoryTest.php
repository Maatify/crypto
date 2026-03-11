<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\DX;

use Maatify\Crypto\DX\CryptoContextFactory;
use Maatify\Crypto\HKDF\Exceptions\InvalidContextException;
use Maatify\Crypto\HKDF\HKDFService;
use Maatify\Crypto\KeyRotation\DTO\CryptoKeyDTO;
use Maatify\Crypto\KeyRotation\KeyRotationService;
use Maatify\Crypto\KeyRotation\KeyStatusEnum;
use Maatify\Crypto\KeyRotation\Policy\StrictSingleActiveKeyPolicy;
use Maatify\Crypto\KeyRotation\Providers\InMemoryKeyProvider;
use Maatify\Crypto\Reversible\Algorithms\Aes256GcmAlgorithm;
use Maatify\Crypto\Reversible\Registry\ReversibleCryptoAlgorithmRegistry;
use PHPUnit\Framework\TestCase;

class CryptoContextFactoryTest extends TestCase
{
    private CryptoContextFactory $factory;

    protected function setUp(): void
    {
        $keys = [
            new CryptoKeyDTO('root_v1', str_repeat('A', 32), KeyStatusEnum::ACTIVE, new \DateTimeImmutable())
        ];

        $rotationService = new KeyRotationService(
            new InMemoryKeyProvider($keys),
            new StrictSingleActiveKeyPolicy()
        );

        $hkdfService = new HKDFService();

        $registry = new ReversibleCryptoAlgorithmRegistry();
        $registry->register(new Aes256GcmAlgorithm());

        $this->factory = new CryptoContextFactory($rotationService, $hkdfService, $registry);
    }

    public function testCreateInstantiatesServiceSuccessfullyWithDerivedKeys(): void
    {
        $service = $this->factory->create('payment:card:v1');

        $encrypted = $service->encrypt('sensitive number');

        $this->assertArrayHasKey('result', $encrypted);
        $this->assertSame('root_v1', $encrypted['key_id']);
    }

    public function testCreateThrowsExceptionOnInvalidContextString(): void
    {
        $this->expectException(InvalidContextException::class);
        $this->factory->create('unversioned_context');
    }
}
