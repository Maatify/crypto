<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\KeyRotation;

use Maatify\Crypto\KeyRotation\DTO\CryptoKeyDTO;
use Maatify\Crypto\KeyRotation\Exceptions\KeyNotFoundException;
use Maatify\Crypto\KeyRotation\Exceptions\MultipleActiveKeysException;
use Maatify\Crypto\KeyRotation\Exceptions\NoActiveKeyException;
use Maatify\Crypto\KeyRotation\KeyStatusEnum;
use Maatify\Crypto\KeyRotation\Providers\InMemoryKeyProvider;
use PHPUnit\Framework\TestCase;

class InMemoryKeyProviderTest extends TestCase
{
    public function testInitializationSucceedsWithOneActiveKey(): void
    {
        $provider = new InMemoryKeyProvider([
            new CryptoKeyDTO('k1', 'mat1', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
            new CryptoKeyDTO('k2', 'mat2', KeyStatusEnum::INACTIVE, new \DateTimeImmutable()),
        ]);

        $this->assertCount(2, $provider->all());
        $this->assertSame('k1', $provider->active()->id());
    }

    public function testInitializationThrowsWhenNoActiveKey(): void
    {
        $this->expectException(NoActiveKeyException::class);

        new InMemoryKeyProvider([
            new CryptoKeyDTO('k1', 'mat1', KeyStatusEnum::INACTIVE, new \DateTimeImmutable()),
        ]);
    }

    public function testInitializationThrowsWhenMultipleActiveKeys(): void
    {
        $this->expectException(MultipleActiveKeysException::class);

        new InMemoryKeyProvider([
            new CryptoKeyDTO('k1', 'mat1', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
            new CryptoKeyDTO('k2', 'mat2', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
        ]);
    }

    public function testFindReturnsKey(): void
    {
        $provider = new InMemoryKeyProvider([
            new CryptoKeyDTO('k1', 'mat1', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
        ]);

        $key = $provider->find('k1');
        $this->assertSame('k1', $key->id());
    }

    public function testFindThrowsWhenKeyNotFound(): void
    {
        $provider = new InMemoryKeyProvider([
            new CryptoKeyDTO('k1', 'mat1', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
        ]);

        $this->expectException(KeyNotFoundException::class);
        $provider->find('k2');
    }

    public function testPromoteSetsNewKeyActiveAndOldKeyInactive(): void
    {
        $provider = new InMemoryKeyProvider([
            new CryptoKeyDTO('k1', 'mat1', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
            new CryptoKeyDTO('k2', 'mat2', KeyStatusEnum::INACTIVE, new \DateTimeImmutable()),
        ]);

        $provider->promote('k2');

        $this->assertSame('k2', $provider->active()->id());
        $this->assertSame(KeyStatusEnum::INACTIVE, $provider->find('k1')->status());
        $this->assertSame(KeyStatusEnum::ACTIVE, $provider->find('k2')->status());
    }

    public function testPromoteThrowsForMissingKey(): void
    {
        $provider = new InMemoryKeyProvider([
            new CryptoKeyDTO('k1', 'mat1', KeyStatusEnum::ACTIVE, new \DateTimeImmutable()),
        ]);

        $this->expectException(KeyNotFoundException::class);
        $provider->promote('missing');
    }
}
