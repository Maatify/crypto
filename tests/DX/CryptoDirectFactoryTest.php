<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\DX;

use Maatify\Crypto\DX\CryptoDirectFactory;
use Maatify\Crypto\KeyRotation\DTO\CryptoKeyDTO;
use Maatify\Crypto\KeyRotation\KeyRotationService;
use Maatify\Crypto\KeyRotation\KeyStatusEnum;
use Maatify\Crypto\KeyRotation\Policy\StrictSingleActiveKeyPolicy;
use Maatify\Crypto\KeyRotation\Providers\InMemoryKeyProvider;
use Maatify\Crypto\Reversible\Algorithms\Aes256GcmAlgorithm;
use Maatify\Crypto\Reversible\Registry\ReversibleCryptoAlgorithmRegistry;
use PHPUnit\Framework\TestCase;

class CryptoDirectFactoryTest extends TestCase
{
    private CryptoDirectFactory $factory;

    protected function setUp(): void
    {
        $keys = [
            new CryptoKeyDTO('root_sys_v1', str_repeat('A', 32), KeyStatusEnum::ACTIVE, new \DateTimeImmutable())
        ];

        $rotationService = new KeyRotationService(
            new InMemoryKeyProvider($keys),
            new StrictSingleActiveKeyPolicy()
        );

        $registry = new ReversibleCryptoAlgorithmRegistry();
        $registry->register(new Aes256GcmAlgorithm());

        $this->factory = new CryptoDirectFactory($rotationService, $registry);
    }

    public function testCreateInstantiatesServiceSuccessfullyWithRawKeys(): void
    {
        $service = $this->factory->create();

        $encrypted = $service->encrypt('raw secret');

        $this->assertArrayHasKey('result', $encrypted);
        $this->assertSame('root_sys_v1', $encrypted['key_id']);
    }
}
