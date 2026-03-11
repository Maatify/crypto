<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation\Exceptions;

/**
 * MultipleActiveKeysException
 *
 * Thrown when more than one ACTIVE key exists.
 */
final class MultipleActiveKeysException extends KeyRotationException
{
}
