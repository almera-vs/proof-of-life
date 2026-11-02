Proof of Life proves that PostgreSQL backups restore. It restores the latest backup into an isolated sandbox, verifies it, measures recovery time, and writes signed evidence for auditors.

## Downloads

| File | For |
|---|---|
| `pol-<version>-linux-amd64` | Linux on x86-64 |
| `pol-<version>-linux-arm64` | Linux on ARM64 |
| `pol-<version>-windows-amd64.exe` | Windows 10 and 11 on x86-64, with Docker Desktop |

Every file is a single executable with no installer. Docker must be running.

## Verify your download

Check the checksum:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

Or check that GitHub built it from this repository:

```bash
gh attestation verify pol-<version>-linux-amd64 --repo almera-vs/proof-of-life
```

The Windows executable is not code-signed, so SmartScreen may warn on first run. Check the checksum before you allow it.

## Licence

MIT with the Commons Clause: free to use, copy and modify, but not to sell, and without warranty. See `LICENSE`, and `THIRD_PARTY_NOTICES.txt` for the components included.

## What's new

See `CHANGELOG.md`.
