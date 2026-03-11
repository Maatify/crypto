# Security Policy

## Supported Versions

Only the latest major version of **maatify/crypto** receives security updates.

| Version | Supported |
| ------- | ---------- |
| 1.x     | ✅ |

---

## Cryptographic Guarantees

The library provides the following strict cryptographic guarantees:

1. **Authenticated Encryption (AEAD)**
   All reversible encryption uses modern AEAD algorithms.
   The default implementation uses **AES-256-GCM**, ensuring confidentiality and integrity.
   Any modification of ciphertext or metadata is detected during decryption.

2. **Domain Separation (HKDF)**
   Context-based encryption derives unique keys using **HKDF (RFC 5869)**.
   Each context (e.g. `auth:session:v1`) produces an independent encryption key, preventing cross-domain compromise.

3. **Secure Password Hashing**
   Passwords are hashed using **Argon2id**.
   The system supports an optional but highly recommended **global pepper** applied via HMAC-SHA256 before hashing.

4. **Fail-Closed Design**
   Any cryptographic failure results in an **immediate exception**.
   The library never:
   - falls back to weaker algorithms
   - silently ignores failures
   - returns partially decrypted data

5. **Key Rotation Safety**
   The system supports multiple keys with lifecycle states:
   - **ACTIVE** – used for encryption
   - **INACTIVE** – preserved for decryption
   - **RETIRED** – legacy decryption only

   Exactly one key must always be **ACTIVE**.

---

## Safe Usage Guidelines

### Protect Your Root Keys and Peppers

The security of this library depends entirely on the secrecy of:

- encryption root keys
- password peppers

Never hardcode them in source code.

Use secure storage mechanisms such as:

- environment variables
- secret managers
- vault systems

---

### Prefer Context-Based Encryption

Always prefer:

```php
$crypto->context("domain:entity:v1");
````

This ensures proper **HKDF domain separation**.

Direct encryption:

```php
$crypto->direct();
```

bypasses HKDF and should only be used for:

* infrastructure secrets
* internal system encryption
* controlled environments where domain separation is unnecessary

---

### Always Handle Exceptions

Cryptographic operations may throw exceptions when:

* ciphertext is corrupted
* authentication tags fail
* keys are missing
* metadata is invalid

These exceptions indicate **security-relevant conditions** and must never be ignored.

---

### Do Not Modify Cryptographic Primitives

The algorithms and primitives in this library are intentionally restricted.

Do **not**:

* replace algorithms
* add fallback ciphers
* inject custom crypto logic

Doing so may introduce severe vulnerabilities.

---

## Reporting a Vulnerability

If you discover a security vulnerability in **maatify/crypto**, please report it responsibly.

**Do not open a public GitHub issue.**

Instead, send a report to:

```
security@maatify.com
```

Please include:

* description of the vulnerability
* steps to reproduce
* affected versions

We will acknowledge receipt within **48 hours** and work with you to resolve the issue responsibly.
