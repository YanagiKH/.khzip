# Recipient keys

Container version 2 supports password and public-key recipient slots. All slots wrap the same random 256-bit archive master key; chunk and manifest encryption remain XChaCha20-Poly1305.

## Algorithms

| CLI name | KEM | Intended use |
|---|---|---|
| `x25519` | DHKEM(X25519, HKDF-SHA256) | Classical interoperability and smaller keys. |
| `ml-kem-768` | ML-KEM-768 with SHAKE128 | Pure post-quantum policy. |
| `x-wing` | ML-KEM-768 + X25519 with TurboSHAKE128 | Recommended hybrid post-quantum default. |

The HPKE AEAD is ChaCha20-Poly1305. Key files are versioned JSON so they can be inspected and migrated without parsing opaque native structures.

## Generate a keypair

```bash
khzip key generate \
  --algorithm x-wing \
  --public backup-recipient.khpub \
  --secret backup-identity.khsec
```

The secret file is written with mode `0600` on Unix. Platform file permissions are not a substitute for full-disk encryption or an offline backup.

Inspect either file:

```bash
khzip key inspect backup-recipient.khpub
```

## Create for one or more recipients

```bash
khzip create Documents \
  --output Documents.khz \
  --recipient alice.khpub \
  --recipient offline-recovery.khpub
```

Add `--password` or `--password-env NAME` to create a separate password slot in the same archive.

## Read with an identity

```bash
khzip verify Documents.khz --identity offline-recovery.khsec
khzip extract Documents.khz --identity alice.khsec --output restored
```

Multiple `--identity` options may be supplied. The archive is unlocked by the first identity whose fingerprint and authenticated HPKE slot match.

## Recovery rules

- Keep secret keys outside the same cloud account as the archives they unlock.
- Back up at least one recovery identity offline.
- Treat a copied secret key as a full transfer of decrypt capability.
- Removing or losing every applicable password and identity makes the archive unrecoverable.
- Rotate recipients by creating a newly encrypted archive; version 0.2 does not mutate slots in place.
