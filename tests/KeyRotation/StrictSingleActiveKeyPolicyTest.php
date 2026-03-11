<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\KeyRotation;

use Maatify\Crypto\KeyRotation\DTO\CryptoKeyDTO;
use Maatify\Crypto\KeyRotation\Exceptions\MultipleActiveKeysException;
use Maatify\Crypto\KeyRotation\Exceptions\NoActiveKeyException;
use Maatify\Crypto\KeyRotation\KeyStatusEnum;
use Maatify\Crypto\KeyRotation\Policy\StrictSingleActiveKeyPolicy;
use PHPUnit\Framework\TestCase;

class StrictSingleActiveKeyPolicyTest extends TestCase
{
    private StrictSingleActiveKeyPolicy $policy;

    protected function setUp(): void
    {
        $this->policy = new StrictSingleActiveKeyPolicy();
    }

    /**
     * @param array<CryptoKeyDTO> $keys
     */
    private function createProvider(array $keys): \Maatify\Crypto\KeyRotation\KeyProviderInterface
    {
        return new class ($keys) implements \Maatify\Crypto\KeyRotation\KeyProviderInterface {
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
                foreach ($this->keys as $key) {
                    if ($key->status() === KeyStatusEnum::ACTIVE) {
                        return $key;
                    }
                }
                throw new NoActiveKeyException();
            }
            public function find(string $id): \Maatify\Crypto\KeyRotation\CryptoKeyInterface
            {
                foreach ($this->keys as $key) {
                    if ($key->id() === $id) {
                        return $key;
                    }
                }
                throw new \Maatify\Crypto\KeyRotation\Exceptions\KeyNotFoundException();
            }
            public function promote(string $id): void
            {
            }
        };
    }

    public function testValidatePassesWithExactlyOneActiveKey(): void
    {
        $provider = $this->createProvider([
            new CryptoKeyDTO('k1', 'mat', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
            new CryptoKeyDTO('k2', 'mat', KeyStatusEnum::INACTIVE, new \DateTimeImmutable()),
        ]);

        $this->policy->validate($provider);
        $this->assertTrue(true); // Reached without exception
    }

    public function testValidateThrowsExceptionWhenNoActiveKeys(): void
    {
        $provider = $this->createProvider([
            new CryptoKeyDTO('k1', 'mat', KeyStatusEnum::INACTIVE, new \DateTimeImmutable()),
        ]);

        $this->expectException(NoActiveKeyException::class);
        $this->expectExceptionMessage('No ACTIVE key exists (invariant violation)');
        $this->policy->validate($provider);
    }

    public function testValidateThrowsExceptionWhenMultipleActiveKeys(): void
    {
        $provider = $this->createProvider([
            new CryptoKeyDTO('k1', 'mat', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
            new CryptoKeyDTO('k2', 'mat', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
        ]);

        $this->expectException(MultipleActiveKeysException::class);
        $this->expectExceptionMessage('Multiple ACTIVE keys exist: 2 (invariant violation)');
        $this->policy->validate($provider);
    }

    public function testEncryptionKeyReturnsActiveKey(): void
    {
        $provider = $this->createProvider([
            new CryptoKeyDTO('k1', 'mat', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
        ]);

        $key = $this->policy->encryptionKey($provider);
        $this->assertSame('k1', $key->id());
    }

    public function testDecryptionKeyThrowsExceptionIfKeyNotFound(): void
    {
        $provider = $this->createProvider([]);

        $this->expectException(\Maatify\Crypto\KeyRotation\Exceptions\KeyNotFoundException::class);
        $this->expectExceptionMessage('Key not found: missing_key');

        $this->policy->decryptionKey($provider, 'missing_key');
    }
}
