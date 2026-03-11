<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\DX;

use Maatify\Crypto\DX\CryptoContextFactory;
use Maatify\Crypto\DX\CryptoDirectFactory;
use Maatify\Crypto\DX\CryptoProvider;
use Maatify\Crypto\HKDF\HKDFService;
use Maatify\Crypto\KeyRotation\DTO\CryptoKeyDTO;
use Maatify\Crypto\KeyRotation\KeyRotationService;
use Maatify\Crypto\KeyRotation\KeyStatusEnum;
use Maatify\Crypto\KeyRotation\Policy\StrictSingleActiveKeyPolicy;
use Maatify\Crypto\KeyRotation\Providers\InMemoryKeyProvider;
use Maatify\Crypto\Reversible\Algorithms\Aes256GcmAlgorithm;
use Maatify\Crypto\Reversible\Registry\ReversibleCryptoAlgorithmRegistry;
use Maatify\Crypto\Reversible\ReversibleCryptoService;
use PHPUnit\Framework\TestCase;

class CryptoProviderTest extends TestCase
{
    private CryptoProvider $provider;

    protected function setUp(): void
    {
        $keys = [new CryptoKeyDTO('key1', str_repeat('A', 32), KeyStatusEnum::ACTIVE, new \DateTimeImmutable())];
        $provider = new InMemoryKeyProvider($keys);
        $policy = new StrictSingleActiveKeyPolicy();
        $rotationService = new KeyRotationService($provider, $policy);

        $hkdfService = new HKDFService();

        $registry = new ReversibleCryptoAlgorithmRegistry();
        $registry->register(new Aes256GcmAlgorithm());

        $contextFactory = new CryptoContextFactory($rotationService, $hkdfService, $registry);
        $directFactory = new CryptoDirectFactory($rotationService, $registry);

        $this->provider = new CryptoProvider($contextFactory, $directFactory);
    }

    public function testContextReturnsConfiguredService(): void
    {
        $service = $this->provider->context('test:domain:v1');

        $this->assertInstanceOf(ReversibleCryptoService::class, $service);

        // Assert that the service works
        $encrypted = $service->encrypt('secret data');
        $this->assertNotEmpty($encrypted['result']->cipher);
    }

    public function testDirectReturnsConfiguredService(): void
    {
        $service = $this->provider->direct();

        $this->assertInstanceOf(ReversibleCryptoService::class, $service);

        // Assert that the service works
        $encrypted = $service->encrypt('internal system secret');
        $this->assertNotEmpty($encrypted['result']->cipher);
    }
}
