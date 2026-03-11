<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\Integration;

use Maatify\Crypto\DX\CryptoContextFactory;
use Maatify\Crypto\HKDF\HKDFService;
use Maatify\Crypto\KeyRotation\DTO\CryptoKeyDTO;
use Maatify\Crypto\KeyRotation\KeyRotationService;
use Maatify\Crypto\KeyRotation\KeyStatusEnum;
use Maatify\Crypto\KeyRotation\Policy\StrictSingleActiveKeyPolicy;
use Maatify\Crypto\KeyRotation\Providers\InMemoryKeyProvider;
use Maatify\Crypto\Reversible\Algorithms\Aes256GcmAlgorithm;
use Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO;
use Maatify\Crypto\Reversible\Registry\ReversibleCryptoAlgorithmRegistry;
use PHPUnit\Framework\TestCase;

class ContextEncryptionPipelineTest extends TestCase
{
    private CryptoContextFactory $factory;

    protected function setUp(): void
    {
        $keys = [
            new CryptoKeyDTO('key_v1', str_repeat('A', 32), KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
            new CryptoKeyDTO('key_v2', str_repeat('A', 32), KeyStatusEnum::INACTIVE, new \DateTimeImmutable()), // Kept for decryption capability
        ];

        $rotationService = new KeyRotationService(
            new InMemoryKeyProvider($keys),
            new StrictSingleActiveKeyPolicy()
        );

        $registry = new ReversibleCryptoAlgorithmRegistry();
        $registry->register(new Aes256GcmAlgorithm());

        $this->factory = new CryptoContextFactory($rotationService, new HKDFService(), $registry);
    }

    public function testEndToEndEncryptionAndDecryptionUsingDerivedKeys(): void
    {
        $contextString = 'auth:session:v1';
        $plaintext = 'user_id=123;role=admin';

        $service = $this->factory->create($contextString);

        // 1. Encrypt
        $encryptionResult = $service->encrypt($plaintext);
        $this->assertSame('key_v1', $encryptionResult['key_id']);

        // 2. Decrypt
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

    public function testDifferentContextsCannotDecryptEachOther(): void
    {
        $plaintext = 'secret string';

        $serviceA = $this->factory->create('domain:a:v1');
        $serviceB = $this->factory->create('domain:b:v1');

        $encryptionResult = $serviceA->encrypt($plaintext);
        $metadata = new ReversibleCryptoMetadataDTO(
            $encryptionResult['result']->iv,
            $encryptionResult['result']->tag
        );

        $this->expectException(\Maatify\Crypto\Reversible\Exceptions\CryptoDecryptionFailedException::class);

        // Try to decrypt data from Service A using Service B's keys
        $serviceB->decrypt(
            $encryptionResult['result']->cipher,
            $encryptionResult['key_id'],
            $encryptionResult['algorithm'],
            $metadata
        );
    }
}
