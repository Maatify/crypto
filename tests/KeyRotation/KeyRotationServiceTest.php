<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\KeyRotation;

use Maatify\Crypto\KeyRotation\DTO\CryptoKeyDTO;
use Maatify\Crypto\KeyRotation\KeyRotationService;
use Maatify\Crypto\KeyRotation\KeyStatusEnum;
use Maatify\Crypto\KeyRotation\Policy\StrictSingleActiveKeyPolicy;
use Maatify\Crypto\KeyRotation\Providers\InMemoryKeyProvider;
use PHPUnit\Framework\TestCase;

class KeyRotationServiceTest extends TestCase
{
    private InMemoryKeyProvider $provider;
    private StrictSingleActiveKeyPolicy $policy;
    private KeyRotationService $service;

    protected function setUp(): void
    {
        $keys = [
            new CryptoKeyDTO('key_1', str_repeat('A', 32), KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
            new CryptoKeyDTO('key_2', str_repeat('B', 32), KeyStatusEnum::INACTIVE, new \DateTimeImmutable()),
            new CryptoKeyDTO('key_3', str_repeat('C', 32), KeyStatusEnum::RETIRED, new \DateTimeImmutable()),
        ];

        $this->provider = new InMemoryKeyProvider($keys);
        $this->policy = new StrictSingleActiveKeyPolicy();
        $this->service = new KeyRotationService($this->provider, $this->policy);
    }

    public function testValidateReturnsSuccessWhenStateIsConsistent(): void
    {
        $result = $this->service->validate();

        $this->assertTrue($result->isValid);
        $this->assertNull($result->errorMessage);
    }

    public function testValidateReturnsFailureWhenNoActiveKeyExists(): void
    {
        $keys = [
            new CryptoKeyDTO('key_1', str_repeat('A', 32), KeyStatusEnum::INACTIVE, new \DateTimeImmutable()),
        ];

        // Setup raw provider to bypass constructor constraints
        $badProvider = new class ($keys) implements \Maatify\Crypto\KeyRotation\KeyProviderInterface {
            /** @var array<CryptoKeyDTO> */
            private array $keys;

            /** @param array<CryptoKeyDTO> $keys */
            public function __construct(array $keys)
            {
                $this->keys = $keys;
            }
            public function all(): iterable
            {
                return $this->keys;
            }
            public function active(): \Maatify\Crypto\KeyRotation\CryptoKeyInterface
            {
                throw new \Maatify\Crypto\KeyRotation\Exceptions\NoActiveKeyException();
            }
            public function find(string $id): \Maatify\Crypto\KeyRotation\CryptoKeyInterface
            {
                throw new \Exception();
            }
            public function promote(string $id): void
            {
            }
        };

        $service = new KeyRotationService($badProvider, $this->policy);
        $result = $service->validate();

        $this->assertFalse($result->isValid);
        $this->assertIsString($result->errorMessage);
        $this->assertStringContainsString('No ACTIVE key exists', $result->errorMessage);
    }

    public function testActiveEncryptionKeyReturnsActiveKey(): void
    {
        $key = $this->service->activeEncryptionKey();

        $this->assertSame('key_1', $key->id());
        $this->assertSame(KeyStatusEnum::ACTIVE, $key->status());
    }

    public function testDecryptionKeyResolvesAllowedKeys(): void
    {
        $active = $this->service->decryptionKey('key_1');
        $inactive = $this->service->decryptionKey('key_2');
        $retired = $this->service->decryptionKey('key_3');

        $this->assertSame('key_1', $active->id());
        $this->assertSame('key_2', $inactive->id());
        $this->assertSame('key_3', $retired->id());
    }

    public function testExportForCryptoOnlyIncludesDecryptableKeys(): void
    {
        $export = $this->service->exportForCrypto();

        $this->assertArrayHasKey('keys', $export);
        $this->assertArrayHasKey('active_key_id', $export);

        $this->assertSame('key_1', $export['active_key_id']);

        $this->assertArrayHasKey('key_1', $export['keys']);
        $this->assertArrayHasKey('key_2', $export['keys']);
        $this->assertArrayHasKey('key_3', $export['keys']);
    }

    public function testSnapshotReturnsCorrectState(): void
    {
        $snapshot = $this->service->snapshot();

        $this->assertSame('key_1', $snapshot->activeKey->id());
        $this->assertCount(1, $snapshot->inactiveKeys);
        $this->assertCount(1, $snapshot->retiredKeys);

        $this->assertSame('key_2', $snapshot->inactiveKeys[0]->id());
        $this->assertSame('key_3', $snapshot->retiredKeys[0]->id());
    }

    public function testRotateToPerformStateChange(): void
    {
        $decision = $this->service->rotateTo('key_2');

        $this->assertTrue($decision->rotationOccurred);
        $this->assertSame('key_2', $decision->newActiveKeyId);
        $this->assertSame('key_1', $decision->previousActiveKeyId);

        // Assert state changed
        $this->assertSame('key_2', $this->service->activeEncryptionKey()->id());
    }

    public function testRotateToSameKeyDoesNothing(): void
    {
        $decision = $this->service->rotateTo('key_1');

        $this->assertFalse($decision->rotationOccurred);
        $this->assertSame('key_1', $decision->newActiveKeyId);
        $this->assertSame('key_1', $decision->previousActiveKeyId);
    }
}
