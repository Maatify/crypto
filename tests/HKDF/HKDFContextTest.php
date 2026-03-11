<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\HKDF;

use Maatify\Crypto\HKDF\Exceptions\InvalidContextException;
use Maatify\Crypto\HKDF\HKDFContext;
use PHPUnit\Framework\TestCase;

class HKDFContextTest extends TestCase
{
    public function testValidContextString(): void
    {
        $context = new HKDFContext('domain:entity:v1');
        $this->assertSame('domain:entity:v1', $context->value());
    }

    public function testContextStringIsTrimmed(): void
    {
        $context = new HKDFContext('  service:data:v2  ');
        $this->assertSame('service:data:v2', $context->value());
    }

    public function testEmptyContextThrowsException(): void
    {
        $this->expectException(InvalidContextException::class);
        $this->expectExceptionMessage('HKDF context must not be empty.');
        new HKDFContext('');
    }

    public function testWhitespaceOnlyContextThrowsException(): void
    {
        $this->expectException(InvalidContextException::class);
        $this->expectExceptionMessage('HKDF context must not be empty.');
        new HKDFContext('   ');
    }

    public function testContextWithoutVersionThrowsException(): void
    {
        $this->expectException(InvalidContextException::class);
        $this->expectExceptionMessage('HKDF context must be versioned (e.g. "email:payload:v1").');
        new HKDFContext('domain:entity');
    }

    public function testOverlyLongContextThrowsException(): void
    {
        $longString = str_repeat('a', 256) . ':v1';
        $this->expectException(InvalidContextException::class);
        $this->expectExceptionMessage('HKDF context is too long.');
        new HKDFContext($longString);
    }
}
