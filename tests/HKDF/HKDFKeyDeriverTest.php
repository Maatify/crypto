<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\HKDF;

use Maatify\Crypto\HKDF\HKDFKeyDeriver;
use PHPUnit\Framework\TestCase;

class HKDFKeyDeriverTest extends TestCase
{
    private HKDFKeyDeriver $deriver;

    protected function setUp(): void
    {
        $this->deriver = new HKDFKeyDeriver();
    }

    public function testDeriveGeneratesCorrectLength(): void
    {
        $rootKey = str_repeat('k', 32);
        $context = 'test:context:v1';

        $derived16 = $this->deriver->derive($rootKey, $context, 16);
        $derived32 = $this->deriver->derive($rootKey, $context, 32);
        $derived64 = $this->deriver->derive($rootKey, $context, 64);

        $this->assertSame(16, strlen($derived16));
        $this->assertSame(32, strlen($derived32));
        $this->assertSame(64, strlen($derived64));
    }

    public function testDeriveIsDeterministic(): void
    {
        $rootKey = str_repeat('x', 32);
        $context = 'auth:token:v2';

        $key1 = $this->deriver->derive($rootKey, $context, 32);
        $key2 = $this->deriver->derive($rootKey, $context, 32);

        $this->assertSame($key1, $key2);
        $this->assertNotEmpty($key1);
    }

    public function testDeriveDomainSeparation(): void
    {
        $rootKey = str_repeat('r', 32);

        $key1 = $this->deriver->derive($rootKey, 'domain:one:v1', 32);
        $key2 = $this->deriver->derive($rootKey, 'domain:two:v1', 32);

        $this->assertNotSame($key1, $key2);
    }
}
