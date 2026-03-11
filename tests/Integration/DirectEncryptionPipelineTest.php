<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\Integration;

use Maatify\Crypto\DX\CryptoDirectFactory;
use Maatify\Crypto\KeyRotation\DTO\CryptoKeyDTO;
use Maatify\Crypto\KeyRotation\KeyRotationService;
use Maatify\Crypto\KeyRotation\KeyStatusEnum;
use Maatify\Crypto\KeyRotation\Policy\StrictSingleActiveKeyPolicy;
use Maatify\Crypto\KeyRotation\Providers\InMemoryKeyProvider;
use Maatify\Crypto\Reversible\Algorithms\Aes256GcmAlgorithm;
use Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO;
use Maatify\Crypto\Reversible\Registry\ReversibleCryptoAlgorithmRegistry;
use PHPUnit\Framework\TestCase;

class DirectEncryptionPipelineTest extends TestCase
{
    private CryptoDirectFactory $factory;

    protected function setUp(): void
    {
        $keys = [
            new CryptoKeyDTO('sys_k1', str_repeat('A', 32), KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
        ];

        $rotationService = new KeyRotationService(
            new InMemoryKeyProvider($keys),
            new StrictSingleActiveKeyPolicy()
        );

        $registry = new ReversibleCryptoAlgorithmRegistry();
        $registry->register(new Aes256GcmAlgorithm());

        $this->factory = new CryptoDirectFactory($rotationService, $registry);
    }

    public function testEndToEndDirectEncryptionAndDecryption(): void
    {
        $plaintext = 'internal-db-password';

        $service = $this->factory->create();

        $encryptionResult = $service->encrypt($plaintext);

        $metadata = new ReversibleCryptoMetadataDTO(
            $encryptionResult['result']->iv,
            $encryptionResult['result']->tag
        );

        $decrypted = $service->decrypt(
            $encryptionResult['result']->cipher,
            $encryptionResult['key_id'],
            $encryptionResult['algorithm'],
            $metadata
        );

        $this->assertSame($plaintext, $decrypted);
    }
}
