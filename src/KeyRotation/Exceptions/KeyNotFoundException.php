<?php

declare(strict_types=1);

namespace Maatify\Crypto\KeyRotation\Exceptions;

/**
 * KeyNotFoundException
 *
 * Thrown when a key_id cannot be resolved by the provider.
 */
final class KeyNotFoundException extends KeyRotationException
{
}
