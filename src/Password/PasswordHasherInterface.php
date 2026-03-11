<?php

declare(strict_types=1);

namespace Maatify\Crypto\Password;

interface PasswordHasherInterface
{
    public function hash(string $plain): string;

    public function verify(string $plain, string $storedHash): bool;

    public function needsRehash(string $storedHash): bool;
}
