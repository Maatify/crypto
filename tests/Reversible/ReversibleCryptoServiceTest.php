<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\Reversible;

use Maatify\Crypto\Reversible\Algorithms\Aes256GcmAlgorithm;
use Maatify\Crypto\Reversible\Exceptions\CryptoAlgorithmNotSupportedException;
use Maatify\Crypto\Reversible\Exceptions\CryptoDecryptionFailedException;
use Maatify\Crypto\Reversible\Exceptions\CryptoKeyNotFoundException;
use Maatify\Crypto\Reversible\Registry\ReversibleCryptoAlgorithmRegistry;
use Maatify\Crypto\Reversible\ReversibleCryptoAlgorithmEnum;
use Maatify\Crypto\Reversible\ReversibleCryptoService;
use PHPUnit\Framework\TestCase;

class ReversibleCryptoServiceTest extends TestCase
{
    private ReversibleCryptoAlgorithmRegistry $registry;

    /** @var array<string, string> */
    private array $keys;

    private string $activeKeyId;

    protected function setUp(): void
    {
        $this->registry = new ReversibleCryptoAlgorithmRegistry();
        $this->registry->register(new Aes256GcmAlgorithm());

        $this->activeKeyId = 'key_v1';
        $this->keys = [
            'key_v1' => str_repeat('A', 32),
            'key_v2' => str_repeat('B', 32),
        ];
    }

    private function createService(ReversibleCryptoAlgorithmEnum $algorithm = ReversibleCryptoAlgorithmEnum::AES_256_GCM): ReversibleCryptoService
    {
        return new ReversibleCryptoService($this->registry, $this->keys, $this->activeKeyId, $algorithm);
    }

    public function testInstantiationFailsIfActiveKeyNotFound(): void
    {
        $this->expectException(CryptoKeyNotFoundException::class);
        $this->expectExceptionMessage('Active crypto key not found: missing_key');

        new ReversibleCryptoService($this->registry, $this->keys, 'missing_key', ReversibleCryptoAlgorithmEnum::AES_256_GCM);
    }

    public function testEncryptReturnsExpectedArrayStructure(): void
    {
        $service = $this->createService();
        $result = $service->encrypt('hello world');

        $this->assertArrayHasKey('result', $result);
        $this->assertArrayHasKey('key_id', $result);
        $this->assertArrayHasKey('algorithm', $result);

        $this->assertSame($this->activeKeyId, $result['key_id']);
        $this->assertSame(ReversibleCryptoAlgorithmEnum::AES_256_GCM, $result['algorithm']);
        $this->assertNotEmpty($result['result']->cipher);
        $this->assertNotEmpty($result['result']->iv);
        $this->assertNotEmpty($result['result']->tag);
    }

    public function testEncryptFailsIfAlgorithmNotRegistered(): void
    {
        $emptyRegistry = new ReversibleCryptoAlgorithmRegistry();

        $service = new ReversibleCryptoService(
            $emptyRegistry,
            $this->keys,
            $this->activeKeyId,
            ReversibleCryptoAlgorithmEnum::AES_256_GCM
        );

        $this->expectException(CryptoAlgorithmNotSupportedException::class);
        $service->encrypt('hello world');
    }

    public function testRoundtripEncryptionDecryption(): void
    {
        $service = $this->createService();

        $plaintext = 'highly sensitive data block';
        $encrypted = $service->encrypt($plaintext);

        $metadata = new \Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO(
            $encrypted['result']->iv,
            $encrypted['result']->tag
        );

        $decrypted = $service->decrypt(
            $encrypted['result']->cipher,
            $encrypted['key_id'],
            $encrypted['algorithm'],
            $metadata
        );

        $this->assertSame($plaintext, $decrypted);
    }

    public function testDecryptThrowsExceptionOnInvalidKeyId(): void
    {
        $service = $this->createService();
        $encrypted = $service->encrypt('test');

        $metadata = new \Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO(
            $encrypted['result']->iv,
            $encrypted['result']->tag
        );

        $this->expectException(CryptoKeyNotFoundException::class);
        $this->expectExceptionMessage('Crypto key not found: fake_key_id');

        $service->decrypt(
            $encrypted['result']->cipher,
            'fake_key_id',
            $encrypted['algorithm'],
            $metadata
        );
    }

    public function testDecryptThrowsCryptoDecryptionFailedExceptionOnCorruptCipher(): void
    {
        $service = $this->createService();
        $encrypted = $service->encrypt('test');

        $metadata = new \Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO(
            $encrypted['result']->iv,
            $encrypted['result']->tag
        );

        $this->expectException(CryptoDecryptionFailedException::class);

        // Mutate the cipher slightly
        $service->decrypt(
            $encrypted['result']->cipher . 'X',
            $encrypted['key_id'],
            $encrypted['algorithm'],
            $metadata
        );
    }

    public function testDecryptThrowsExceptionOnUnregisteredAlgorithm(): void
    {
        $service = $this->createService();
        $encrypted = $service->encrypt('test');

        $metadata = new \Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO(
            $encrypted['result']->iv,
            $encrypted['result']->tag
        );

        $emptyRegistry = new ReversibleCryptoAlgorithmRegistry();
        $failingService = new ReversibleCryptoService($emptyRegistry, $this->keys, $this->activeKeyId, ReversibleCryptoAlgorithmEnum::AES_256_GCM);

        $this->expectException(CryptoAlgorithmNotSupportedException::class);
        $failingService->decrypt(
            $encrypted['result']->cipher,
            $encrypted['key_id'],
            ReversibleCryptoAlgorithmEnum::AES_256_GCM,
            $metadata
        );
    }
}
