<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\HKDF;

use Maatify\Crypto\HKDF\Exceptions\InvalidOutputLengthException;
use Maatify\Crypto\HKDF\Exceptions\InvalidRootKeyException;
use Maatify\Crypto\HKDF\HKDFContext;
use Maatify\Crypto\HKDF\HKDFService;
use PHPUnit\Framework\TestCase;

class HKDFServiceTest extends TestCase
{
    private HKDFService $service;

    protected function setUp(): void
    {
        $this->service = new HKDFService();
    }

    public function testDeriveKeySuccessfullyGeneratesKeyOfCorrectLength(): void
    {
        $rootKey = str_repeat('A', 32);
        $context = new HKDFContext('test:domain:v1');

        $derivedKey = $this->service->deriveKey($rootKey, $context, 32);

        $this->assertSame(32, strlen($derivedKey));
    }

    public function testDeriveKeyIsDeterministic(): void
    {
        $rootKey = str_repeat('A', 32);
        $context = new HKDFContext('test:domain:v1');

        $key1 = $this->service->deriveKey($rootKey, $context, 32);
        $key2 = $this->service->deriveKey($rootKey, $context, 32);

        $this->assertSame($key1, $key2);
    }

    public function testDeriveKeyProvidesDomainSeparation(): void
    {
        $rootKey = str_repeat('A', 32);

        $key1 = $this->service->deriveKey($rootKey, new HKDFContext('test:domain1:v1'), 32);
        $key2 = $this->service->deriveKey($rootKey, new HKDFContext('test:domain2:v1'), 32);

        $this->assertNotSame($key1, $key2);
    }

    public function testDeriveKeyEnforcesRootKeyLengthPolicy(): void
    {
        $rootKey = str_repeat('A', 31); // Too short
        $context = new HKDFContext('test:domain:v1');

        $this->expectException(InvalidRootKeyException::class);
        $this->service->deriveKey($rootKey, $context, 32);
    }

    public function testDeriveKeyEnforcesOutputLengthPolicyTooLarge(): void
    {
        $rootKey = str_repeat('A', 32);
        $context = new HKDFContext('test:domain:v1');

        $this->expectException(InvalidOutputLengthException::class);
        $this->service->deriveKey($rootKey, $context, 65); // SHA-256 limit is 64 in policy
    }

    public function testDeriveKeyEnforcesOutputLengthPolicyTooSmall(): void
    {
        $rootKey = str_repeat('A', 32);
        $context = new HKDFContext('test:domain:v1');

        $this->expectException(InvalidOutputLengthException::class);
        $this->service->deriveKey($rootKey, $context, 0);
    }
}
