<?php

declare(strict_types=1);

namespace Maatify\Crypto\Tests\Reversible;

use Maatify\Crypto\Reversible\Algorithms\Aes256GcmAlgorithm;
use Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO;
use Maatify\Crypto\Reversible\Exceptions\CryptoDecryptionFailedException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class Aes256GcmAlgorithmTest extends TestCase
{
    private Aes256GcmAlgorithm $algorithm;

    protected function setUp(): void
    {
        $this->algorithm = new Aes256GcmAlgorithm();
    }

    public function testEncryptGeneratesCorrectLengths(): void
    {
        $key = str_repeat('A', 32);
        $result = $this->algorithm->encrypt('test', $key);

        $this->assertSame(12, strlen($result->iv));
        $this->assertSame(16, strlen($result->tag));
        $this->assertNotEmpty($result->cipher);
    }

    public function testEncryptThrowsExceptionForInvalidKeyLength(): void
    {
        $key = str_repeat('A', 31); // Too short

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid AES-256-GCM key length: expected 32 bytes, got 31');

        $this->algorithm->encrypt('test', $key);
    }

    public function testDecryptThrowsExceptionForInvalidKeyLength(): void
    {
        $key = str_repeat('A', 31);
        $metadata = new ReversibleCryptoMetadataDTO('iv1234567890', 'tag1234567890123');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid AES-256-GCM key length: expected 32 bytes, got 31');

        $this->algorithm->decrypt('cipher', $key, $metadata);
    }

    public function testRoundtripEncryptionDecryption(): void
    {
        $key = str_repeat('A', 32);
        $plaintext = 'sensitive data payload';

        $encrypted = $this->algorithm->encrypt($plaintext, $key);

        $metadata = new ReversibleCryptoMetadataDTO($encrypted->iv, $encrypted->tag);
        $decrypted = $this->algorithm->decrypt($encrypted->cipher, $key, $metadata);

        $this->assertSame($plaintext, $decrypted);
    }

    public function testDecryptThrowsExceptionForMissingMetadata(): void
    {
        $key = str_repeat('A', 32);
        $encrypted = $this->algorithm->encrypt('test', $key);

        // Missing IV
        $metadata = new ReversibleCryptoMetadataDTO(null, $encrypted->tag);

        $this->expectException(CryptoDecryptionFailedException::class);
        $this->expectExceptionMessage('Missing IV or authentication tag for AES-256-GCM decryption');

        $this->algorithm->decrypt($encrypted->cipher, $key, $metadata);
    }

    public function testDecryptThrowsExceptionForInvalidTagLength(): void
    {
        $key = str_repeat('A', 32);
        $encrypted = $this->algorithm->encrypt('test', $key);

        $metadata = new ReversibleCryptoMetadataDTO($encrypted->iv, 'short_tag'); // Too short tag

        $this->expectException(CryptoDecryptionFailedException::class);
        $this->expectExceptionMessage('Invalid AES-256-GCM authentication tag length: expected 16 bytes, got 9');

        $this->algorithm->decrypt($encrypted->cipher, $key, $metadata);
    }

    public function testDecryptThrowsExceptionWhenTagIsMismatched(): void
    {
        $key = str_repeat('A', 32);
        $encrypted = $this->algorithm->encrypt('test payload', $key);

        // Create an invalid tag of exact 16 bytes
        $invalidTag = str_repeat('B', 16);
        $metadata = new ReversibleCryptoMetadataDTO($encrypted->iv, $invalidTag);

        $this->expectException(CryptoDecryptionFailedException::class);
        $this->expectExceptionMessage('AES-256-GCM authentication failed or data corrupted');

        $this->algorithm->decrypt($encrypted->cipher, $key, $metadata);
    }
}
