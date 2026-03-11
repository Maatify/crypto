# Maatify Crypto

[![Latest Version](https://img.shields.io/packagist/v/maatify/crypto.svg?style=for-the-badge)](https://packagist.org/packages/maatify/crypto)
[![PHP Version](https://img.shields.io/packagist/php-v/maatify/crypto.svg?style=for-the-badge)](https://packagist.org/packages/maatify/crypto)
[![License](https://img.shields.io/github/license/Maatify/crypto?style=for-the-badge)](LICENSE)

![PHPStan](https://img.shields.io/badge/PHPStan-Level%20Max-4E8CAE)

[![Changelog](https://img.shields.io/badge/Changelog-View-blue)](CHANGELOG.md)
[![Security](https://img.shields.io/badge/Security-Policy-important)](SECURITY.md)

![Monthly Downloads](https://img.shields.io/packagist/dm/maatify/crypto?label=Monthly%20Downloads&color=00A8E8)
![Total Downloads](https://img.shields.io/packagist/dt/maatify/crypto?label=Total%20Downloads&color=2AA9E0)

[![Security Audit](https://img.shields.io/badge/Security-Audited-green?style=for-the-badge)](SECURITY_AUDIT.md)

![Security First](https://img.shields.io/badge/Security-Cryptography-darkred?style=for-the-badge)
![Maatify Ecosystem](https://img.shields.io/badge/Maatify-Ecosystem-blueviolet?style=for-the-badge)

[![Install](https://img.shields.io/badge/Install-composer%20require-blue?style=for-the-badge)](https://packagist.org/packages/maatify/crypto)

---

# Installation

```bash
composer require maatify/crypto
````

---

# Quick Example

```php
use Maatify\Crypto\DX\CryptoProvider;
use Maatify\Crypto\Reversible\DTO\ReversibleCryptoMetadataDTO;

$crypto = $container->get(CryptoProvider::class);

$service = $crypto->context("user:email:v1");

$encrypted = $service->encrypt("hello world");

$metadata = new ReversibleCryptoMetadataDTO(
    $encrypted['result']->iv,
    $encrypted['result']->tag
);

$plain = $service->decrypt(
    $encrypted['result']->cipher,
    $encrypted['key_id'],
    $encrypted['algorithm'],
    $metadata
);
```

---

# Documentation

For full documentation and detailed usage guides, see the official documentation book:

➡️ **[Documentation Book](docs/book/index.md)**

The documentation includes:

- Architecture overview
- Key rotation lifecycle
- Context-based encryption
- Password hashing pipeline
- Security design guarantees
- Integration examples

---

# 1. Overview

This library is a **Security-First cryptographic system** providing a set of strict, isolated, and frozen cryptographic primitives. It is designed to be extracted as a standalone library, independent of any specific application framework.

The system enforces a **strict separation of concerns** between key lifecycle management, key derivation, reversible encryption, and password hashing. It prioritizes **safety, deterministic behavior, and fail-closed security** over developer convenience.

All cryptographic primitives within this library are **frozen**, meaning their core logic, algorithms, and security boundaries are immutable. Any significant change to these primitives requires a formal architectural review.

---

# Cryptographic Design

The library follows modern cryptographic best practices:

* AES-256-GCM authenticated encryption
* HKDF domain separation (RFC 5869)
* Argon2id password hashing
* Secure randomness via `random_bytes()`
* Strict key rotation lifecycle (Active / Inactive / Retired)
* Fail-closed cryptographic operations

---

# 2. Library Breakdown

The cryptographic system is composed of five distinct, decoupled components:

---

## 1. Password Component (`Password/`)

**Purpose:** Secure, irreversible password hashing and verification.

**What it DOES**

Implements a strict pipeline of:

```
HMAC-SHA256 (Pepper) → Argon2id
```

Handles:

* hashing
* verification
* rehash checks

**What it DOES NOT do**

* manage storage of hashes
* retrieve pepper secrets

**Security Boundary**

Operates in total isolation from encryption keys and relies on:

```
PasswordPepperProviderInterface
```

---

## 2. KeyRotation Module (`KeyRotation/`)

**Purpose:** Management of cryptographic key lifecycles and rotation policies.

**What it DOES**

Enforces strict invariants:

```
exactly one ACTIVE key at any time
```

Manages key states:

* ACTIVE
* INACTIVE
* RETIRED

This allows seamless key rotation without downtime.

**What it DOES NOT do**

* perform encryption or decryption
* load keys from storage

**Security Boundary**

Acts as the sole authority on **which key may encrypt new data**.

---

## 3. HKDF Module (`HKDF/`)

**Purpose:** Key Derivation Function implementing **RFC 5869**.

**What it DOES**

Derives independent keys from a root key using **explicit contexts**.

Example contexts:

```
notification:email:v1
auth:session:v1
payment:token:v1
```

**What it DOES NOT do**

* generate root secrets
* perform encryption

**Security Boundary**

Ensures compromise of one domain **cannot affect another**.

---

## 4. Reversible Module (`Reversible/`)

**Purpose:** Symmetric encryption and decryption.

Algorithm:

```
AES-256-GCM
```

**What it DOES**

* encrypt data
* decrypt data

**What it DOES NOT do**

* manage keys
* derive keys

**Security Boundary**

Fail-closed behavior:

* invalid tag → exception
* corrupted ciphertext → exception
* unsupported algorithm → exception

Weak algorithms like **ECB are explicitly forbidden**.

---

## 5. DX Module (`DX/`)

**Purpose:** Developer Experience orchestration layer.

Provides the `CryptoProvider` facade.

Example:

```php
$crypto->context("user:email:v1");
```

**What it DOES**

Connects primitives into usable pipelines.

**What it DOES NOT do**

Contains **no cryptographic logic**.

All security guarantees exist in the lower layers.

---

# 3. Architectural Flow

The library supports three secure pipelines.

---

## A. Password Hashing Pipeline

Used for authentication.

```
Input Password
   ↓
HMAC-SHA256 (Pepper)
   ↓
Argon2id (Salted)
   ↓
Password Hash
```

---

## B. Context-Based Encryption Pipeline (Recommended)

Used for sensitive application data.

```
Root Keys (KeyRotation)
       ↓
HKDF (Context)
       ↓
Derived Keys
       ↓
AES-256-GCM Encryption
```

---

## C. Direct Encryption Pipeline (Advanced)

Used only for internal system secrets.

```
Root Keys (KeyRotation)
       ↓
AES-256-GCM
```

---

# Key Hierarchy

**Root Keys**

Managed by KeyRotation.

Never used directly for domain data in the standard pipeline.

**Derived Keys**

Generated via HKDF.

Used for actual encryption.

**Password Secrets**

Pepper is **fully isolated** from encryption keys.

---

# 4. Design Principles

**Fail-Closed Behavior**

All modules throw exceptions on failure.

No silent failures.
No fallback algorithms.

---

**Explicit Versioning**

Contexts must be versioned.

Example:

```
auth:token:v1
```

---

**Domain Separation**

Different data domains must use different contexts.

---

**Key Rotation Safety**

Old keys remain valid for decryption while new data always uses the active key.

---

**No Implicit Defaults**

Algorithms, keys, and contexts must always be explicit.

---

**No Hidden State**

Modules are stateless.

They do not cache secrets or persist runtime state.

---

# 5. What This Library Is NOT

**Not a Framework**

No dependency on Laravel, Symfony, etc.

---

**Not a Key Management System**

Does not store keys.

Keys must be injected by the host application.

---

**Not a Secrets Loader**

Does not read `.env`.

Secret management belongs to the host application.

---

**Not a Generic Crypto DSL**

The library intentionally exposes **specific approved primitives** only:

* AES-256-GCM
* Argon2id
* HKDF

No driver abstraction.

---

# 6. Stability & Extraction Readiness

This library is **production-ready**.

It was designed from the start to be **extractable as a standalone package**.

---

**Frozen Components**

* Password
* KeyRotation
* HKDF
* Reversible

Their security contracts are locked.

---

**Optional Components**

DX layer is optional.

Consumers may wire primitives manually.

---

# Stability

This library is production-ready and follows **Semantic Versioning**.
