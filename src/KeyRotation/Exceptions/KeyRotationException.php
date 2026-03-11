<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation\Exceptions;

use RuntimeException;

/**
 * Base exception for Key Rotation failures.
 *
 * ALL failures MUST be fail-closed.
 */
class KeyRotationException extends RuntimeException
{
}
