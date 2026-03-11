<?php

declare(strict_types=1);

namespace Maatify\Crypto\HKDF;

final class HKDFService
{
    private HKDFKeyDeriver $deriver;

    public function __construct(?HKDFKeyDeriver $deriver = null)
    {
        $this->deriver = $deriver ?? new HKDFKeyDeriver();
    }

    public function deriveKey(
        string $rootKey,
        HKDFContext $context,
        int $length
    ): string {
        HKDFPolicy::assertValidRootKey($rootKey);
        HKDFPolicy::assertValidOutputLength($length);

        return $this->deriver->derive(
            $rootKey,
            $context->value(),
            $length
        );
    }
}
