<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\Password;

use Maatify\Crypto\Password\DTO\ArgonPolicyDTO;
use Maatify\Crypto\Password\Exception\InvalidArgonPolicyException;
use PHPUnit\Framework\TestCase;

class ArgonPolicyDTOTest extends TestCase
{
    public function testCreatesValidPolicy(): void
    {
        $policy = new ArgonPolicyDTO(1024, 2, 1);

        $this->assertSame(1024, $policy->memoryCost);
        $this->assertSame(2, $policy->timeCost);
        $this->assertSame(1, $policy->threads);

        $options = $policy->toNativeOptions();
        $this->assertSame(1024, $options['memory_cost']);
        $this->assertSame(2, $options['time_cost']);
        $this->assertSame(1, $options['threads']);
    }

    public function testThrowsExceptionOnInvalidMemoryCost(): void
    {
        $this->expectException(InvalidArgonPolicyException::class);
        $this->expectExceptionMessage('Argon memoryCost must be > 0');
        new ArgonPolicyDTO(0, 2, 1);
    }

    public function testThrowsExceptionOnInvalidTimeCost(): void
    {
        $this->expectException(InvalidArgonPolicyException::class);
        $this->expectExceptionMessage('Argon timeCost must be > 0');
        new ArgonPolicyDTO(1024, 0, 1);
    }

    public function testThrowsExceptionOnInvalidThreads(): void
    {
        $this->expectException(InvalidArgonPolicyException::class);
        $this->expectExceptionMessage('Argon threads must be > 0');
        new ArgonPolicyDTO(1024, 2, 0);
    }
}
