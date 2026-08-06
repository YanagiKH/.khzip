# .khzip product design

## Product promise

`.khzip` creates compact, restorable archives that remain private on untrusted storage. It is built around an explicit recovery model: every archive states how it can be unlocked, verification is a first-class operation, and destructive assumptions are avoided.

## Primary users

- Individuals keeping encrypted cloud backups without trusting the cloud provider.
- Teams sharing large project archives with several named recipients.
- Developers packaging deduplicated assets and reproducible data sets.
- Operators who need split transport files, integrity checks, and offline recovery procedures.

## Core jobs

1. Select content without accidentally following symbolic links.
2. Choose a format and compression policy without understanding codec internals.
3. Choose one or more unlock methods: password, recipient public keys, or the local device key.
4. Create atomically, then verify before deleting or moving source data.
5. Restore safely without path traversal or implicit overwrite.

## Interaction model

The desktop creator follows three visible stages:

1. **Content** — add files or folders and review the exact roots included.
2. **Archive policy** — choose format, compression, destination, and split behavior.
3. **Access** — add a password, one or more recipient public keys, or use the device key required by `.khcz`.

The primary action remains disabled until content and an output path exist. Security warnings are placed beside the relevant choice rather than in a distant help screen.

## Recommended defaults

- Format: `.khz`.
- Compression: Balanced.
- Recipient algorithm: X-Wing hybrid post-quantum.
- Archive access: at least two independent recovery methods for important data, such as an offline recipient key plus a password stored in a password manager.
- Overwrite: disabled.
- Symbolic links: rejected.

## Format positioning

| Format | Product role |
|---|---|
| `.khz` | Default encrypted or unencrypted archive for sharing and backup. |
| `.khpak` | Deliberately unencrypted package for assets and software data. |
| `.khx` | Split transport archive; splitting is not encryption. |
| `.khaz` | Extreme compression with two record-encryption layers and mandatory access control. |
| `.khcz` | Local device-key archive for unattended cloud backup. |

## Safety language

The product never claims that a successful create command proves long-term recoverability. The completion message reports what was written; users are directed to run `verify` and a test extraction. CI success is engineering evidence, not an independent cryptographic audit.

## Accessibility

- Controls use text labels, not color alone.
- The flow is keyboard reachable through native egui controls.
- Status and error messages are persistent text.
- Security choices use explicit names and concise consequences.
- SVG diagrams include meaningful alternative text where embedded in Markdown.
