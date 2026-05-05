# Contributing to i2p-cs-renewed

Thank you for your interest in contributing to **i2p-cs-renewed** — an experimental C# (.NET 10)
implementation of the I2P anonymous overlay network protocol.

---

## Hey, @samueldaaaarling! 👋

We noticed you have a fork of this project and we'd love to collaborate with you directly. If you're
open to it, please consider:

- **Enabling pull requests and issues** on your fork so contributors can send you improvements and
  bug reports.
- **Opening a PR back here** with any enhancements or fixes you've developed — even rough work in
  progress is welcome.

We're happy to share:

- Our **`copilot-instructions`** (in `.github/copilot-instructions.md`), which describe the
  architecture, coding conventions, known broken areas (SSU2, ECIES), and guidance for AI-assisted
  development on this codebase.
- The **roadmap and contribution guidelines** below, so we can coordinate efforts and avoid
  duplicate work.

Feel free to ping us in a PR or issue — developer-to-developer, no ceremony required. 🤝

---

## Project Status

| Area | Status |
|---|---|
| NTCP2 transport | ✅ Working |
| SSU2 transport | ❌ Broken (contributions welcome) |
| ECIES-X25519 session | 🔧 ~70% — needs end-to-end data transfer fix |
| ML-KEM / CRYSTALS-Kyber | 🧪 Experimental |
| SAM bridge / HTTP proxy | 🔧 Depends on ECIES fix |
| Web dashboard (Razor Pages) | ✅ Working |

---

## Getting Started

### Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- An i2pd or Java I2P router running locally (for integration tests only)

### Build

```sh
dotnet restore
dotnet build --no-restore
```

### Run unit tests

```sh
dotnet test --no-build --filter "Category!=Integration&Category!=ScaledNetwork"
```

Integration tests (`[Category("Integration")]` and `[Category("ScaledNetwork")]`) require a live
i2pd instance and are excluded from CI.

---

## Coding Conventions

- **Language**: C# 13, `net10.0` target framework.
- **Nullable references**: enabled in `I2PRouterWeb` and `I2PRouterCli`; not in `I2PCore` / `I2CP`.
- **Naming**: `PascalCase` public members, `_camelCase` private fields, `Async` suffix on all new
  async methods.
- **Logging**: use `I2PCore.Utils.Logging` static methods (`Logging.LogDebug`, etc.) — **not**
  `ILogger<T>` or Serilog.
- **Crypto**: use existing `BouncyCastle.Cryptography` primitives or the custom `I2PCore.Crypto`
  implementations. Do not add new crypto without cross-checking against the
  [I2P specification](https://geti2p.net/spec/).
- **Buffers**: prefer `ArrayPool<byte>.Shared` for allocations > 64 bytes in hot network paths.
- **DI**: `Microsoft.Extensions.DependencyInjection` in `I2PRouterWeb` only; core library uses
  static singletons.

---

## Roadmap Highlights

1. **Fix SSU2** — the UDP transport is entirely non-functional; fixing the handshake against i2pd
   is the top priority.
2. **Complete ECIES session encryption** — unblock HTTP proxy and server-side tunnel flows.
3. **Reduce memory usage** — NTCP2 makes excessive `new byte[]` allocations; migrate hot paths to
   `ArrayPool`.
4. **Improve CI** — update the GitHub Actions workflow from `dotnet-version: 5.0.x` to
   `dotnet-version: 10.0.x` (currently broken).
5. **ML-KEM integration tests** — add automated round-trip tests for NTCP2-PQ handshake.

---

## Pull Request Guidelines

- Keep PRs focused — one logical change per PR.
- Add or update unit tests for any new behaviour.
- Run `dotnet build` and unit tests before opening the PR.
- Reference any relevant I2P spec section or i2pd source file in the PR description.
- Draft PRs are welcome — open early, iterate in the open.

---

## Questions?

Open an issue or start a discussion. All experience levels welcome.
