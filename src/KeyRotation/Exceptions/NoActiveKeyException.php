<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation\Exceptions;

/**
 * NoActiveKeyException
 *
 * Thrown when zero ACTIVE keys exist.
 */
final class NoActiveKeyException extends KeyRotationException
{
}
