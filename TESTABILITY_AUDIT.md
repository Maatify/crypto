# Crypto Testability Report

This document outlines the testability audit of the `Maatify\Crypto` module. The module has been designed with strict cryptographic primitives, clear interfaces, and injected dependencies, making it highly testable.

## 1. Component Analysis

### PasswordHasher
* **Purpose:** Provides secure, irreversible password hashing and verification using an HMAC-SHA256 (Pepper) → Argon2id pipeline.
* **Public API:**
  * `hash(string $plain): string`
  * `verify(string $plain, string $storedHash): bool`
  * `needsRehash(string $storedHash): bool`
* **What must be tested:**
  * Successfully hashing a password to an Argon2id format.
  * Successfully verifying a correct plaintext against a hash.
  * Rejecting an incorrect plaintext against a valid hash.
  * `needsRehash` behavior when policies change vs when they remain the same.
  * Throwing `PepperUnavailableException` when the pepper provider returns an empty string.
  * Throwing `HashingFailedException` when the internal `password_hash` fails.
* **What cannot be tested:**
  * The internal C-level execution of `password_hash` or `hash_hmac` (this is the domain of PHP core tests).
* **Possible edge cases:**
  * Extremely long passwords, empty passwords, and passwords with multibyte/Unicode characters.
  * Malformed stored hashes during verification.
* **Required test fixtures:**
  * Mock or stub for `PasswordPepperProviderInterface`.
  * Concrete `ArgonPolicyDTO` instance with minimal cost settings (e.g., memory=1024, time=1, threads=1) to ensure tests execute quickly.

### HKDFService
* **Purpose:** Orchestrates the Key Derivation Function (RFC 5869) for domain separation, ensuring roots and contexts meet security policies before derivation.
* **Public API:**
  * `deriveKey(string $rootKey, HKDFContext $context, int $length): string`
* **What must be tested:**
  * Generating a derived key of the exact requested length.
  * Determinism: same root key + same context = identical derived key.
  * Domain separation: different contexts = different derived keys.
  * Exception `InvalidRootKeyException` if root key length is < 32 bytes.
  * Exception `InvalidOutputLengthException` if length is invalid (e.g., > 64 bytes).
* **What cannot be tested:**
  * Cryptographic collisions in SHA-256.
* **Possible edge cases:**
  * Output length strictly at the maximum allowed boundary (64 bytes).
  * Root keys exactly at the minimum boundary (32 bytes).
* **Required test fixtures:**
  * Minimum 32-byte pseudo-random string for a valid root key.
  * Valid `HKDFContext` instances (e.g., `"test:domain:v1"`).

### ReversibleCryptoService
* **Purpose:** Orchestrates reversible symmetric cryptography (AES-GCM), routing encryption and decryption to the registered active algorithm and resolving appropriate keys.
* **Public API:**
  * `encrypt(string $plain): array`
  * `decrypt(string $cipher, string $keyId, ReversibleCryptoAlgorithmEnum $algorithmEnum, ReversibleCryptoMetadataDTO $metadata): string`
* **What must be tested:**
  * Successful encryption returns ciphertext, IV, tag, active key ID, and algorithm.
  * Successful decryption using the exact output parts of `encrypt()` restores the original plaintext.
  * Throwing `CryptoKeyNotFoundException` if instantiated with an active key ID missing from the key array, or during decryption.
  * Throwing `CryptoAlgorithmNotSupportedException` if the algorithm is missing from the registry.
  * Throwing `CryptoDecryptionFailedException` when provided corrupted ciphertext, invalid authentication tags, missing metadata, or the wrong key.
* **What cannot be tested:**
  * OpenSSL internals breaking AES-256-GCM.
* **Possible edge cases:**
  * Empty string plaintext.
  * Decryption attempt with an incorrect algorithm enum but otherwise valid data.
* **Required test fixtures:**
  * A configured `ReversibleCryptoAlgorithmRegistry` injected with `Aes256GcmAlgorithm`.
  * Pre-generated array of valid 32-byte binary keys mapped by ID.

### ReversibleCryptoAlgorithmRegistry
* **Purpose:** A centralized, fail-closed registry binding allowed reversible crypto algorithm enums to their concrete implementations.
* **Public API:**
  * `register(ReversibleCryptoAlgorithmInterface $algorithm): void`
  * `get(ReversibleCryptoAlgorithmEnum $algorithm): ReversibleCryptoAlgorithmInterface`
  * `has(ReversibleCryptoAlgorithmEnum $algorithm): bool`
  * `list(): array`
* **What must be tested:**
  * `register()` correctly adds an algorithm making it accessible via `get()`, `has()`, and `list()`.
  * Registering the same enum twice throws `CryptoAlgorithmNotSupportedException`.
  * `get()` for an unregistered enum throws `CryptoAlgorithmNotSupportedException`.
* **What cannot be tested:** N/A.
* **Possible edge cases:**
  * Instantiating and querying an empty registry.
* **Required test fixtures:**
  * Mock/Stub implementations of `ReversibleCryptoAlgorithmInterface`.

### KeyRotationService
* **Purpose:** Orchestrates lifecycle decisions, performs state validations, and exports keys in a format ready for cryptography without executing actual encryption/decryption.
* **Public API:**
  * `validate(): KeyRotationValidationResultDTO`
  * `activeEncryptionKey(): CryptoKeyInterface`
  * `decryptionKey(string $keyId): CryptoKeyInterface`
  * `exportForCrypto(): array`
  * `snapshot(): KeyRotationStateDTO`
  * `rotateTo(string $newActiveKeyId): KeyRotationDecisionDTO`
* **What must be tested:**
  * `validate()` returns a successful DTO when exactly one ACTIVE key exists, and a failure DTO if invariant checks fail.
  * `exportForCrypto()` outputs ONLY keys that have decryption enabled, mapped by ID.
  * `activeEncryptionKey()` correctly leverages the policy to fetch the ACTIVE key.
  * `decryptionKey()` successfully retrieves INACTIVE or RETIRED keys (if allowed by policy).
  * `rotateTo()` triggers a policy state change and accurately reports rotation occurrence.
* **What cannot be tested:**
  * Real database or Vault persistence mechanisms (this module is purely domain logic).
* **Possible edge cases:**
  * `rotateTo()` targeting an ID that is already ACTIVE.
  * Requesting a `decryptionKey()` for a key with a DESTROYED status.
* **Required test fixtures:**
  * `InMemoryKeyProvider` pre-populated with `CryptoKeyDTO` instances in various states (ACTIVE, INACTIVE, RETIRED, DESTROYED).
  * `StrictSingleActiveKeyPolicy`.

### CryptoProvider
* **Purpose:** Serves as a unified Developer Experience (DX) facade, exposing injection points for specific encryption pipelines.
* **Public API:**
  * `context(string $context): ReversibleCryptoService`
  * `direct(): ReversibleCryptoService`
* **What must be tested:**
  * `context()` successfully passes the string to `CryptoContextFactory` and returns a `ReversibleCryptoService`.
  * `direct()` successfully triggers `CryptoDirectFactory` and returns a `ReversibleCryptoService`.
* **What cannot be tested:**
  * Internal factory logic (tested elsewhere).
* **Possible edge cases:**
  * Invalid context strings passed into `context()`.
* **Required test fixtures:**
  * Mocks of `CryptoContextFactory` and `CryptoDirectFactory`.

### CryptoContextFactory
* **Purpose:** Automates the wiring of `KeyRotation` -> `HKDF` -> `ReversibleCrypto`, deriving context-specific keys safely.
* **Public API:**
  * `create(string $contextString, ReversibleCryptoAlgorithmEnum $algorithm): ReversibleCryptoService`
* **What must be tested:**
  * Factory calls `exportForCrypto()`, invokes `HKDFService` for each root key, and returns an instantiated `ReversibleCryptoService` loaded with derived keys rather than raw root keys.
  * Context strings without a version indicator (e.g. `:v1`) cause instantiation to fail via `HKDFContext`.
* **What cannot be tested:**
  * Mathematical entropy of the derived keys (tested at HKDF level).
* **Possible edge cases:**
  * Returning 0 keys from the rotation provider.
* **Required test fixtures:**
  * Mock `KeyRotationService` returning deterministic fake keys.
  * `HKDFService` instance.

### CryptoDirectFactory
* **Purpose:** Automates the wiring of `KeyRotation` -> `ReversibleCrypto`, feeding raw root keys directly into the crypto service.
* **Public API:**
  * `create(ReversibleCryptoAlgorithmEnum $algorithm): ReversibleCryptoService`
* **What must be tested:**
  * Factory calls `exportForCrypto()` and immediately maps raw root keys into a new `ReversibleCryptoService`.
* **What cannot be tested:** N/A.
* **Possible edge cases:**
  * Key array from the rotation service missing the active key ID.
* **Required test fixtures:**
  * Mock `KeyRotationService`.

---

## 2. Test Coverage Map

**Unit Tests:**
* `Password/`
  * `PasswordHasherTest`
  * `ArgonPolicyDTOTest`
* `HKDF/`
  * `HKDFServiceTest`
  * `HKDFKeyDeriverTest`
  * `HKDFPolicyTest`
  * `HKDFContextTest`
* `Reversible/`
  * `ReversibleCryptoServiceTest`
  * `ReversibleCryptoAlgorithmRegistryTest`
  * `Aes256GcmAlgorithmTest`
* `KeyRotation/`
  * `KeyRotationServiceTest`
  * `StrictSingleActiveKeyPolicyTest`
  * `InMemoryKeyProviderTest`
* `DX/`
  * `CryptoProviderTest`
  * `CryptoContextFactoryTest`
  * `CryptoDirectFactoryTest`

**Integration Tests:**
* `ContextEncryptionPipelineTest`: Tests the flow of `Root Key -> HKDF -> Reversible Encryption -> Decryption`.
* `DirectEncryptionPipelineTest`: Tests the flow of `Root Key -> Reversible Encryption -> Decryption`.
* `PasswordPipelineTest`: Tests the flow of `Pepper Injection -> HMAC -> Argon2id`.

---

## 3. Estimated Number of Test Files
**18 test files** (15 Unit + 3 Integration).

## 4. Estimated Number of Tests
**~75 tests** covering successful workflows, expected exception throwing, and exact boundary condition checks.

## 5. Refactoring Required to Enable Testing
**None.**
The module strictly adheres to SOLID principles, dependency inversion via interfaces, statelessness, and pure functional configuration. It does not rely on global helpers (like framework `env()` or `config()`), making it perfectly decoupled and fully ready for PHPUnit or Pest testing without requiring structural modifications.
