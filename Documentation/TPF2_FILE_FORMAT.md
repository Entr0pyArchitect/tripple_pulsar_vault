# TPF2 / TPF3 Vault File Format Specification

TripplePulsar Vault currently supports two on-disk container families:

- **TPF2** for legacy and TPV 2.0-compatible vaults
- **TPF3** for the modern extensible format used by TPV 3.0

This document reflects the **current codebase** and is intended to match the active Rust implementation.

---

## 1. Format Selection

Vault parsing is selected by the first four bytes of the file:

- `TPF2` → parse as `Tpf2Header`
- `TPF3` → parse as `Tpf3Header`

If neither magic value is present, parsing fails.

---

## 2. TPF2 Overview

TPF2 is the compact legacy-compatible format.

### File Layout

A `.tpf2` vault is:

```text
+-------------------+
| Header (62 bytes) |
+-------------------+
| AEAD payload      |
+-------------------+
```

The AEAD payload is the output returned by AES-256-GCM. In practice this is the encrypted plaintext with the authentication tag appended by the AEAD implementation.

### Supported Versions

- **v1**: legacy vaults
- **v2**: current TPV 2.0 vaults

### Fixed Header Size

`62 bytes`

### TPF2 Header Layout

| Offset | Size | Field | Type | Notes |
|---|---:|---|---|---|
| 0 | 4 | `magic` | bytes | ASCII `TPF2` |
| 4 | 1 | `version` | u8 | `1` for legacy, `2` for current |
| 5 | 1 | `flags` | u8 | feature flags |
| 6 | 1 | `alg_id` | u8 | canonical value `1` = AES-256-GCM |
| 7 | 1 | `kdf_id` | u8 | canonical value `1` = Argon2id |
| 8 | 4 | `kdf_m` | u32 LE | Argon2 memory cost in KiB |
| 12 | 2 | `kdf_t` | u16 LE | Argon2 time cost |
| 14 | 1 | `kdf_p` | u8 | Argon2 parallelism |
| 15 | 1 | `tpm_flag` | u8 | reserved TPM indicator |
| 16 | 2 | `reserved` | bytes | reserved, currently zeroed |
| 18 | 32 | `os_salt` | bytes | random salt |
| 50 | 12 | `nonce` | bytes | AES-GCM nonce |

### Algorithm Identifiers

#### Encryption

| ID | Meaning |
|---|---|
| 1 | AES-256-GCM |

The parser also tolerates `0` for compatibility, but newly created vaults write the canonical value `1`.

#### KDF

| ID | Meaning |
|---|---|
| 1 | Argon2id |

The parser also tolerates `0` for compatibility, but newly created vaults write the canonical value `1`.

### Key Derivation

TPF2 supports two key schedules depending on header version.

#### TPF2 v1

Legacy vaults use the direct Argon2id output as the AES-256-GCM key.

```text
dataset_hash = optional BLAKE3(dataset)
IKM = passphrase || dataset_hash
vault_key = Argon2id(IKM, os_salt, kdf_m, kdf_t, kdf_p)
```

#### TPF2 v2

Current TPV 2.0 vaults derive a 32-byte Argon2id root key and then expand the actual encryption key with HKDF-SHA256.

```text
dataset_hash = optional BLAKE3(dataset)
IKM = passphrase || dataset_hash
root_key = Argon2id(IKM, os_salt, kdf_m, kdf_t, kdf_p)
vault_key = HKDF-SHA256(
  salt = os_salt,
  ikm = root_key,
  info = "TPV2:ENC:AES-256-GCM"
)
```

### Authenticated Encryption

TPF2 uses **AES-256-GCM**.

The serialized 62-byte header is bound as **Associated Authenticated Data (AAD)**:

```text
payload = AES-256-GCM-Encrypt(
  key = vault_key,
  nonce = nonce,
  plaintext = file_data,
  aad = header_bytes
)
```

Any modification to the header or encrypted payload causes authentication failure during decryption.

---

## 3. TPF3 Overview

TPF3 is the modern extensible format introduced for TPV 3.0. It adds:

- multiple cipher suites
- explicit key-wrap modes
- variable-length header-attached blobs
- a dedicated Argon2id + HKDF-SHA256 key schedule

### File Layout

A `.tpf3` vault is:

```text
+---------------------------+
| Fixed header (56 bytes)   |
+---------------------------+
| nonce                     |
+---------------------------+
| wrapped_key               |
+---------------------------+
| kem_ciphertext            |
+---------------------------+
| tpm_policy                |
+---------------------------+
| AEAD payload              |
+---------------------------+
```

The payload begins at:

```text
body_offset = 56 + nonce_len + wrapped_key_len + kem_ct_len + tpm_policy_len
```

### Fixed Header Size

`56 bytes`

### TPF3 Fixed Header Layout

| Offset | Size | Field | Type | Notes |
|---|---:|---|---|---|
| 0 | 4 | `magic` | bytes | ASCII `TPF3` |
| 4 | 1 | `version` | u8 | currently `1` |
| 5 | 2 | `flags` | u16 LE | feature flags |
| 7 | 1 | `cipher_id` | u8 | cipher suite |
| 8 | 1 | `kdf_id` | u8 | KDF identifier |
| 9 | 1 | `wrap_mode` | u8 | key-wrap mode |
| 10 | 1 | `nonce_len` | u8 | bytes in nonce blob |
| 11 | 2 | `wrapped_key_len` | u16 LE | bytes in wrapped key blob |
| 13 | 2 | `kem_ct_len` | u16 LE | bytes in KEM ciphertext blob |
| 15 | 2 | `tpm_policy_len` | u16 LE | bytes in TPM policy blob |
| 17 | 4 | `kdf_m` | u32 LE | Argon2 memory cost in KiB |
| 21 | 2 | `kdf_t` | u16 LE | Argon2 time cost |
| 23 | 1 | `kdf_p` | u8 | Argon2 parallelism |
| 24 | 32 | `os_salt` | bytes | random salt |

### Variable-Length Blob Order

Immediately after the fixed header, the following blobs are serialized in this order:

1. `nonce`
2. `wrapped_key`
3. `kem_ciphertext`
4. `tpm_policy`

### Cipher Suite Identifiers

| ID | Meaning | Nonce Length |
|---|---|---:|
| 1 | AES-256-GCM | 12 |
| 2 | XChaCha20-Poly1305 | 24 |

### KDF Identifiers

| ID | Meaning |
|---|---|
| 1 | Argon2id + HKDF-SHA256 |

### Wrap Mode Identifiers

| ID | Meaning |
|---|---|
| 0 | None |
| 1 | TPM-wrapped key |
| 2 | ML-KEM-768 wrapped key |

### TPF3 Validation Rules

The implementation validates the following:

- nonce length must match the selected cipher suite
- `wrap_mode = None` requires empty `kem_ciphertext` and empty `tpm_policy`
- `wrap_mode = TpmWrapped` requires a non-empty `wrapped_key` and an empty `kem_ciphertext`
- `wrap_mode = MlKem768` requires non-empty `wrapped_key` and non-empty `kem_ciphertext`, and an empty `tpm_policy`

### Key Derivation

For the currently implemented **direct/local derivation** mode (`wrap_mode = None`):

```text
dataset_hash = optional BLAKE3(dataset)
IKM = passphrase || dataset_hash
root_key = Argon2id(IKM, os_salt, kdf_m, kdf_t, kdf_p)
content_key = HKDF-SHA256(
  salt = os_salt,
  ikm = root_key,
  info = cipher-specific label
)
```

HKDF info labels currently used:

- `TPF3:ENC:AES-256-GCM`
- `TPF3:ENC:XCHACHA20-POLY1305`

### Authenticated Encryption

TPF3 binds the **entire serialized TPF3 header** as AAD.

For AES-256-GCM:

```text
payload = AES-256-GCM-Encrypt(
  key = content_key,
  nonce = nonce,
  plaintext = file_data,
  aad = serialized_tpf3_header
)
```

For XChaCha20-Poly1305:

```text
payload = XChaCha20-Poly1305-Encrypt(
  key = content_key,
  nonce = nonce,
  plaintext = file_data,
  aad = serialized_tpf3_header
)
```

---

## 4. Current Implementation Status

### Implemented

- TPF2 encrypt / decrypt / inspect
- TPF3 encrypt / decrypt / inspect
- TPF3 direct/local derivation (`wrap_mode = None`)
- TPF3 AES-256-GCM
- TPF3 XChaCha20-Poly1305
- TPM provider detection and TPM RSA key provisioning utilities

### Defined in Format, Not Yet Wired End-to-End

- TPF3 TPM-wrapped content key encryption/decryption
- TPF3 ML-KEM-768 wrapped content key encryption/decryption

The format reserves space for wrapped-key metadata today, but the current CLI only performs full TPF3 encryption/decryption for direct/local derivation mode.

---

## 5. Security Notes

- If a dataset is used during encryption, the same dataset must be supplied during decryption.
- Authentication must be verified before returning plaintext.
- Header fields are authenticated through AEAD AAD binding.
- Overwrite-based deletion is best-effort only and is not guaranteed on SSDs or other wear-leveling storage.

---

## 6. Summary

TPF2 remains the compact backward-compatible vault format, while TPF3 provides the forward-looking extensible container for TPV 3.0.

The current codebase supports both formats and dispatches parsing strictly by file magic.
