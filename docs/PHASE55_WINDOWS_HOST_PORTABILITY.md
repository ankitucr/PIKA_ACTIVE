# Phase 55: Windows and POSIX host portability

## Objective

PIKA PC integration targets Windows as well as Termux/Linux. Unconditional `fcntl` imports prevented core result-attestation and host-attestor modules from loading on Windows, so this phase standardizes process locking.

## Changes

- Adds a shared `core.portable_lock` backend.
- Uses POSIX `flock` on Linux/Termux/macOS.
- Uses Windows `msvcrt.locking` byte-range locks on Windows. Shared requests serialize as exclusive locks on Windows.
- Moves the Phase 36 replay guard and host-attestor audit/nonce journals to the portable lock backend.
- Makes POSIX permission-bit checks conditional on POSIX, matching the existing owner-file validation behavior on Windows.
- Keeps no-symlink checks, owner identity checks where supported, hash-chained journals, replay rejection and bounded file sizes.

## Validation

The Phase 55 test forces the Windows lock backend with a fake `msvcrt` implementation and exercises the actual result-attestation replay guard. It also imports the host-attestor modules to catch unconditional POSIX-only imports.

## Limits

The Windows lock backend is tested through a controlled compatibility fixture in Linux CI; a native Windows runner is still required for full OS-level validation. The host attestor's Podman/Docker isolation remains a separate prerequisite.

This phase does not enable third-party dependency installation. Unpinned external imports remain rejected.
