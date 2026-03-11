<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\HKDF;

use Maatify\Crypto\HKDF\Exceptions\InvalidOutputLengthException;
use Maatify\Crypto\HKDF\Exceptions\InvalidRootKeyException;
use Maatify\Crypto\HKDF\HKDFPolicy;
use PHPUnit\Framework\TestCase;

class HKDFPolicyTest extends TestCase
{
    public function testAssertValidRootKeyPassesForValidKey(): void
    {
        $key = str_repeat('a', 32);
        HKDFPolicy::assertValidRootKey($key);
        $this->assertTrue(true); // Reached without exception
    }

    public function testAssertValidRootKeyThrowsExceptionForShortKey(): void
    {
        $key = str_repeat('a', 31);
        $this->expectException(InvalidRootKeyException::class);
        $this->expectExceptionMessage('Root key length is insufficient for HKDF.');
        HKDFPolicy::assertValidRootKey($key);
    }

    public function testAssertValidOutputLengthPassesForValidLengths(): void
    {
        HKDFPolicy::assertValidOutputLength(1);
        HKDFPolicy::assertValidOutputLength(32);
        HKDFPolicy::assertValidOutputLength(64);
        $this->assertTrue(true); // Reached without exception
    }

    public function testAssertValidOutputLengthThrowsForZeroLength(): void
    {
        $this->expectException(InvalidOutputLengthException::class);
        HKDFPolicy::assertValidOutputLength(0);
    }

    public function testAssertValidOutputLengthThrowsForNegativeLength(): void
    {
        $this->expectException(InvalidOutputLengthException::class);
        HKDFPolicy::assertValidOutputLength(-5);
    }

    public function testAssertValidOutputLengthThrowsForExcessiveLength(): void
    {
        $this->expectException(InvalidOutputLengthException::class);
        HKDFPolicy::assertValidOutputLength(65);
    }
}
