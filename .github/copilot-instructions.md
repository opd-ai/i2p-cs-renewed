# Project Overview

i2p-cs-renewed is an experimental C# (.NET 10) implementation of the I2P (Invisible Internet Project) anonymous overlay network protocol. It is a fork of [i2p-cs](https://github.com/PeterZander/i2p-cs) extended to add post-quantum cryptography (NTCP2-PQ with ML-KEM/CRYSTALS-Kyber), SSU2 UDP transport, and a web-based router dashboard. The project implements the full I2P protocol stack: transport layer (NTCP2 and SSU2), tunnel layer (garlic routing, build, relay), network database (NetDB with Kademlia DHT floodfill), session layer (ECIES-X25519 and MLKEM768-X25519 end-to-end encryption), and client proxies (SAM bridge, I2CP, HTTP proxy, SOCKS).

The target audience is developers experimenting with I2P protocol implementations in .NET. The project is explicitly marked as experimental ("slop-fork"), is not intended for production use, and acknowledges significant incompleteness: SSU2 is entirely broken, ECIES session encryption is 70% working, and memory usage is high. Comparison against Java I2P, i2pd, and go-i2p implementations is the intended benchmark. The deployment model is self-hosted on a user machine or server (Linux/Windows/macOS via .NET 10 runtime).

## Technical Stack

- **Primary Language**: C# (.NET 10)
- **Target Framework(s)**: `net10.0` (all projects)
- **Nullable Reference Types**: Enabled only in `I2PRouterWeb` and `I2PRouterCli`; **not** enabled in `I2PCore` or `I2CP`
- **Web Framework**: ASP.NET Core Razor Pages (`I2PRouterWeb`; Kestrel-hosted, no MVC or API controllers)
- **Data Access**: None (no database; router state is held in memory and flat files)
- **Database**: None
- **Authentication**: None (local router dashboard, no user auth)
- **Testing Frameworks**: NUnit 4.4.0 with NUnit3TestAdapter 6.1.0 and Microsoft.NET.Test.Sdk 18.0.1
- **Mocking**: None (tests use real implementations or lightweight stubs)
- **Assertion Libraries**: NUnit built-in assertions (`Assert`, `ClassicAssert`)
- **Logging**: Custom `I2PCore.Utils.Logging` static class — **not** Serilog, NLog, or `Microsoft.Extensions.Logging`; configured via `app.config` (System.Configuration) in core projects and via `appsettings.json` + direct `Logging.*` calls in the web project
- **DI Container**: `Microsoft.Extensions.DependencyInjection` in `I2PRouterWeb` only; core library uses no DI container
- **Build/Deploy**: GitHub Actions (`.github/workflows/dotnet.yml`); **note: the CI workflow specifies `dotnet-version: 5.0.x` but the solution targets `net10.0` — CI is currently broken and does not provide quality gating**
- **Key NuGet Packages**:
  - `BouncyCastle.Cryptography` 2.7.0-beta.98 — elliptic-curve, ElGamal, AES, and low-level byte-manipulation crypto primitives (**pre-release; use with caution**)
  - `System.Configuration.ConfigurationManager` 10.0.2 — `app.config`-based settings for `I2PCore` and `I2CP`
  - `NUnit` 4.4.0 / `NUnit3TestAdapter` 6.1.0 — test runner

## Code Assistance Guidelines

1. **Async/Await Patterns**
   - Use `async Task<T>` / `async Task` for all I/O-bound operations (network sockets, file reads).
   - Suffix all new async methods with `Async` (e.g., `SendMessageAsync`), consistent with the existing convention in the codebase (note: some older methods do not follow this; do not rename them without specific refactoring intent).
   - Pass `CancellationToken` parameters through all async call chains; honour cancellation before and after every `await`.
   - Because `I2PCore` is a library, use `.ConfigureAwait(false)` on all `await` calls within `I2PCore` and `I2CP` to avoid deadlocks when called from sync contexts.
   - Example:
   ```csharp
   public async Task<bool> SendFrameAsync(byte[] data, CancellationToken cancellationToken = default)
   {
       await _stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
       return true;
   }
   ```

2. **Nullable Reference Types**
   - `I2PRouterWeb` and `I2PRouterCli` have `<Nullable>enable</Nullable>`. Do not introduce new `CS86xx` warnings in these projects.
   - `I2PCore` and `I2CP` do **not** enable nullable; do not add `#nullable enable` directives to individual files unless part of a targeted migration.
   - In nullable-enabled projects: use `?` for nullable references, avoid the null-forgiving operator (`!`) except where essential, and prefer pattern matching for null checks: `if (value is null)` / `if (value is not null)`.
   - Example (nullable-enabled project):
   ```csharp
   public RouterInfo? FindRouter(I2PIdentHash hash)
   {
       if (hash is null) throw new ArgumentNullException(nameof(hash));
       return _store.TryGetValue(hash, out var info) ? info : null;
   }
   ```

3. **Dependency Injection (Web Project Only)**
   - Register services in `Program.cs` using appropriate lifetimes:
     - `Singleton`: `RouterService`, `NetDbLogService`, and other stateful router-wide services.
     - `Scoped` / `Transient`: short-lived per-request handlers if added.
   - Use constructor injection in Razor Page models and services; avoid `IServiceProvider` service-locator calls.
   - `I2PCore` itself uses **no DI container**; class interdependencies are resolved through static singletons (`RouterContext.Inst`, `Router.*`, `NetDb.Inst`) and constructor injection of collaborators.

4. **Cryptography and Protocol Implementation**
   - All cryptographic operations must use established primitives: `BouncyCastle.Cryptography` for ElGamal, EC operations, and AES; custom implementations in `I2PCore.Crypto` for ChaCha20Poly1305, HKDF, X25519, SHA3, Noise XK, and ML-KEM (CRYSTALS-Kyber 512/768/1024).
   - Never introduce a new cryptographic primitive implementation without cross-checking against the I2P specification ([geti2p.net/spec](https://geti2p.net/spec/)) and, where relevant, the i2pd C++ reference implementation.
   - Use `ArrayPool<byte>.Shared` or `MemoryPool<byte>.Shared` for large, short-lived byte buffers in transport-layer code. The NTCP2 layer has excessive `new byte[]` heap allocations that contribute to the documented memory issues; prefer pooling for any new allocations over 64 bytes in hot paths.
   - Conditional compilation constants such as `NOLOG_ALL_TUNNEL_TRANSFER`, `NOLOG_MUCH_TRANSPORT`, and `NOLOG_ALL_IDENT_LOOKUPS` gate verbose logging in `I2PCore.csproj`. Use these when adding trace-level logs so they can be compiled out in production.

5. **Logging**
   - Use `I2PCore.Utils.Logging` directly (static methods: `Logging.LogDebug(...)`, `Logging.LogInformation(...)`, `Logging.LogWarning(...)`, `Logging.LogError(...)`).
   - Do **not** use `Microsoft.Extensions.Logging.ILogger` in `I2PCore` or `I2CP`; those projects do not take a DI dependency.
   - In `I2PRouterWeb`, use `Logging.*` directly (as in `Program.cs`) rather than `ILogger<T>` to remain consistent with the rest of the codebase.
   - Guard verbose logs with conditional constants or a log-level check to avoid performance impact in hot network paths.

6. **Error Handling**
   - Use exception-based error handling throughout; the project has custom exception types: `ChecksumFailureException`, `EndOfStreamEncounteredException`, `FailedToConnectException`, `RouterUnresolvable`, `SignatureCheckFailureException`. Throw these (or extend them) rather than inventing new generic exceptions.
   - Do **not** use a `Result<T>` pattern; it is not used anywhere in the codebase.
   - Wrap external I/O boundaries (socket reads, file access) with `try/catch` and log failures at the appropriate level before rethrowing or returning a sentinel value.
   - Preserve inner exceptions when wrapping: `throw new FailedToConnectException("...", innerException)`.

7. **Naming Conventions**
   - `PascalCase` for all public members, classes, namespaces, properties, events, and delegates.
   - `_camelCase` (underscore prefix) for private instance fields (e.g., `_ipBlockFilter`, `_listenerRestartRequested`).
   - `camelCase` (no prefix) for local variables and method parameters.
   - `I` prefix for interfaces (e.g., `ITransport`, `ITransportProtocol`, `IClient`, `ILeaseSet`).
   - `Async` suffix for all new async methods.
   - I2P-protocol classes follow the `I2P` prefix convention for data types (e.g., `I2PIdentHash`, `I2PRouterInfo`, `I2PLeaseSet2`).

## Project-Specific Context

1. **Solution Structure and Layer Dependencies**
   - `I2PCore` → core protocol stack (no external project dependencies beyond NuGet packages).
   - `I2CP` → I2CP host (depends on `I2PCore`).
   - `I2PRouterWeb` / `I2PRouterCli` → router hosts (depend on `I2PCore` + `I2CP`).
   - `I2PCore.NTests` → test suite (depends on `I2PCore` + `I2CP`).
   - `src/Samples/*` → standalone sample console apps (depend on `I2PCore` and/or `I2CP`).
   - Internal layers within `I2PCore`: `Crypto` → `Data` → `TransportLayer` (NTCP2/SSU2) → `TunnelLayer` → `NetDb` → `SessionLayer` → `Client`.

2. **Test Organization**
   - Unit tests live directly in `src/I2PCore.NTests/` (e.g., `NTCP2HandshakeTest.cs`, `GarlicTest.cs`, `KadDHTTest.cs`).
   - Integration tests live in `src/I2PCore.NTests/IntegrationTests/` and are tagged `[Category("Integration")]`. They require a running i2pd instance and the C# router to be started via `TestNetworkFixture`; they **do not run in CI** and must not be run without the live network setup.
   - When adding tests, place unit tests at the top level of `I2PCore.NTests` and integration tests under `IntegrationTests/`, applying `[Category("Integration")]`.

3. **Configuration Sources**
   - `I2PCore` reads configuration from `app.config` via `System.Configuration.ConfigurationManager`. Router settings (ports, keys, logging levels, bandwidth caps) are stored in `I2PCore.Utils.I2PConfig` and `RouterContext`.
   - `I2PRouterWeb` uses `appsettings.json` / `appsettings.Development.json` for standard ASP.NET Core hosting configuration (log levels, `AllowedHosts`). Router-specific settings flow through `WebRouterSettings`.
   - There is no Azure Key Vault, secrets manager, or environment-variable-based secrets system; sensitive router private keys are stored in files managed by `RouterContext`.

4. **Known Broken Areas — Do Not Regress**
   - **SSU2** (`src/I2PCore/TransportLayer/SSU2/`): both inbound and outbound are marked "totally broken" in the README. Changes here require extreme care; do not claim SSU2 works without verified handshake completion against a live i2pd peer.
   - **GatewayTunnel**: `GatewayTunnel.HandleReceiveQueue()` has a confirmed CS0114 method-hiding bug (missing `override`/`new` keyword at `src/I2PCore/TunnelLayer/GatewayTunnel.cs`). Fixes must add `override` only if the intent is virtual dispatch; otherwise use `new` to silence the warning explicitly.
   - **ECIES/MLKEM session encryption**: `ECIESSessionKeyManager.cs` and `Session.cs` are 70% functional. End-to-end data transfer via ECIES or MLKEM does not reliably work; HTTP proxy and server tunnel functionality depend on this being fixed first.
   - **Memory usage**: NTCP2 transport makes excessive `new byte[]` heap allocations. When touching transport code, prefer `ArrayPool<byte>.Shared.Rent()`/`Return()` for buffers.

5. **I2P Protocol References**
   - All protocol-level implementations must follow the published I2P specifications at [https://geti2p.net/spec/](https://geti2p.net/spec/). Key specs: NTCP2 (`/spec/ntcp2`), SSU2 (`/spec/ssu2`), I2NP (`/spec/i2np`), LeaseSet (`/spec/leaseset`), Streaming (`/spec/streaming`), Garlic (`/spec/tunnel-message`).
   - The i2pd C++ implementation ([https://github.com/PurpleI2P/i2pd](https://github.com/PurpleI2P/i2pd)) is the primary reference for behaviour not fully specified in the spec documents.
   - Post-quantum components (ML-KEM 512/768/1024) follow [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) and the I2P NTCP2-PQ proposal.
