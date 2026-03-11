# SECURITY_AUDIT.md

## 1. Executive Summary

This document presents the findings of a comprehensive, read-only security audit of the `maatify/crypto` library prior to its v1.0.0 release. The audit focused on evaluating the cryptographic primitives, architectural isolation, fail-closed enforcement, and API design. The library demonstrates a highly secure, well-structured, and defense-in-depth approach to cryptography. Only minor, low-severity API risks were identified, and no critical or high-severity vulnerabilities exist. The library is secure and ready for public release.

## 2. Audit Scope

The scope of this audit covers the entire `src/` directory, specifically focusing on:

- Cryptographic Primitive Safety (AES-GCM implementations)
- HKDF Domain Separation
- Password Hashing Security
- Key Rotation Safety
- Encryption / Decryption Safety
- API Misuse Risk (DX module)
- Randomness & Entropy
- Fail-Closed Behavior
- Dependency Review
- Test Coverage Adequacy

All actions performed during this audit were strictly read-only.

## 3. Security Findings

No critical or high-severity issues were found. The codebase implements rigorous controls and strong isolation.

**Finding 3.1 - Misuse potential of `direct()` encryption pipeline**
- **Severity:** Low
- **Description:** The `CryptoProvider` exposes a `direct()` method which bypasses HKDF domain separation, using root keys directly for encryption via `CryptoDirectFactory`. While this is explicitly documented as an advanced pipeline meant for internal secrets, inexperienced developers might use `direct()` instead of `context()` out of convenience, leading to a lack of domain separation.
- **Impact:** If `direct()` is misused across different domains, compromising a key in one domain could allow decrypting data in another.

## 4. Verified Safe Design Decisions

The library employs several excellent, verifiable security decisions:

- **Cryptographic Primitives:** The default and recommended algorithm is AES-256-GCM (AEAD cipher). The implementation uses the correct constraints: 256-bit (32 bytes) key length, 96-bit (12 bytes) IV length generated safely via `random_bytes()`, and requires a 128-bit (16 bytes) authentication tag. Weak modes like ECB are explicitly absent. `OPENSSL_RAW_DATA` is used correctly.
- **Domain Separation (HKDF):** The library uses standard RFC 5869 HMAC-SHA256 for key derivation. Contexts must be explicitly versioned (e.g., `:v1`), non-empty, and limited in length, ensuring tight domain boundaries.
- **Password Hashing:** Implements a robust pipeline of HMAC-SHA256 (Pepper) followed by Argon2id. The pepper is required, missing peppers throw exceptions immediately, and constant-time `password_verify` is used.
- **Key Rotation Invariants:** Enforced perfectly via `StrictSingleActiveKeyPolicy`. The system strictly validates that only *exactly one* ACTIVE key exists for encryption, while INACTIVE and RETIRED keys are preserved correctly for decryption.
- **Fail-Closed Principle:** Exception handling is flawless. No operation falls back to weaker algorithms, returns false silently, or gracefully degrades. OpenSSL false returns, missing metadata, invalid lengths, and unregistered algorithms immediately throw explicit exceptions.
- **RNG:** Predictable RNG functions (`rand`, `mt_rand`) are entirely absent. Entropy relies strictly on `random_bytes()`.
- **Dependencies:** `composer.json` is clean, enforcing PHP `^8.2` and the necessary extensions (`ext-openssl`, `ext-sodium`), without risky runtime dependencies.

## 5. Potential Risks (if any)

- **Developer Convenience vs Security:** As noted in finding 3.1, providing the `direct()` method poses a minor risk if developers bypass domain separation when they shouldn't.

## 6. Recommendations

- **Documentation & DX Warnings:** Continue emphasizing in the documentation the dangers of `direct()` versus `context()`. Consider adding a PHPDoc `@warning` annotation to the `direct()` method in `CryptoProvider` to ensure IDEs highlight the risk of bypassing domain separation.

## 7. Final Security Assessment

The `maatify/crypto` library exhibits exceptional code quality and security posture. It successfully adheres to its stated goals of providing strict, decoupled, fail-closed, and isolated cryptographic primitives. The architecture perfectly separates key lifecycle management from the encryption routines.

**Conclusion:** The library is highly secure and is approved for the v1.0.0 release.