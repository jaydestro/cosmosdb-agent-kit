---
title: Validate Cosmos DB SDK Version Currency
impact: HIGH
impactDescription: prevents known bugs, performance regressions, and security issues present in outdated SDK versions
tags: sdk, versioning, dependency-management, reliability, multi-language
---

## Validate Cosmos DB SDK Version Currency

Cosmos DB SDKs ship frequent minor releases with bug fixes, performance improvements, and security patches. Validate the version declared in the package manifest against the live public registry at review time — never hardcode a specific version in this skill rule, as it goes stale the moment a new release ships.

**Incorrect (outdated pin, unsafe range, or missing companion):**

```xml
<!-- .csproj — behind the latest minor, missing security patches -->
<PackageReference Include="Microsoft.Azure.Cosmos" Version="3.35.0" />

<!-- Newtonsoft.Json on a CVE-affected version -->
<PackageReference Include="Newtonsoft.Json" Version="10.0.3" />
```

```json
// package.json — loose caret range; resolved version is non-deterministic without a lock file
"@azure/cosmos": "^3.0.0"
```

**Correct (latest stable, tightly pinned, lock file committed):**

```xml
<!-- Directory.Packages.props — one place to manage versions across the whole repo -->
<PackageVersion Include="Microsoft.Azure.Cosmos" Version="[fetched from NuGet at review time]" />
<!-- Explicit companion, minimum 13.0.3 — never 10.x (known CVE) -->
<PackageVersion Include="Newtonsoft.Json" Version="[fetched from NuGet at review time]" />
```

```json
// Tilde: allows only patch updates within the declared minor
"@azure/cosmos": "~3.40.0"
```

**Rule 1: Fetch the current latest from the public registry — never hardcode a version in this rule**

A skill rule that contains a specific version string becomes incorrect the moment the SDK ships a new release. Use `fetch_webpage` to retrieve the latest stable version at review time from the appropriate registry, then compare against the manifest.

| Language / framework | Package | Registry query URL |
|---|---|---|
| .NET | `Microsoft.Azure.Cosmos` | `https://api.nuget.org/v3-flatcontainer/microsoft.azure.cosmos/index.json` |
| Python | `azure-cosmos` | `https://pypi.org/pypi/azure-cosmos/json` |
| Node.js / TypeScript | `@azure/cosmos` | `https://registry.npmjs.org/@azure/cosmos/latest` |
| Java (Maven / Gradle) | `com.azure:azure-cosmos` | `https://search.maven.org/solrsearch/select?q=g:com.azure+AND+a:azure-cosmos&rows=1&wt=json` |
| Java (Spring Data) | `com.azure.spring:spring-cloud-azure-starter-data-cosmos` | `https://search.maven.org/solrsearch/select?q=g:com.azure.spring+AND+a:spring-cloud-azure-starter-data-cosmos&rows=1&wt=json` |
| Go | `github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos` | latest tag: `https://github.com/Azure/azure-sdk-for-go/releases?q=azcosmos` |
| Rust | `azure_data_cosmos` | `https://crates.io/api/v1/crates/azure_data_cosmos` — parse `crate.newest_version` |
| Apache Spark connector | `com.azure.cosmos.spark:azure-cosmos-spark_3-5_2-12` | `https://search.maven.org/solrsearch/select?q=g:com.azure.cosmos.spark+AND+a:azure-cosmos-spark_3-5_2-12&rows=1&wt=json` — adjust suffix for your Spark/Scala version |
| Apache Kafka connector | `com.azure.cosmos.kafka:kafka-connect-cosmos` | `https://search.maven.org/solrsearch/select?q=g:com.azure.cosmos.kafka+AND+a:kafka-connect-cosmos&rows=1&wt=json` |
| .NET companion | `Newtonsoft.Json` | `https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json` — must be ≥ 13.0.3; **never use 10.x** (known CVE) |

**Rule 2: Classify the gap and propose the corrected declaration**

After fetching the latest version, classify the difference and emit the corrected snippet using the actual version retrieved:

| Situation | Classification | Action |
|---|---|---|
| Manifest major < latest | BREAKING | Flag as high-priority; link to SDK migration guide |
| Manifest minor < latest | OUTDATED | Propose minor upgrade; link to changelog |
| Manifest patch < latest | STALE PATCH | Propose patch update — likely a bug or security fix |
| Manifest == latest | UP TO DATE | No action |
| Loose range (`^`, `>=`) without lock file | UNSAFE | Tighten to `major.minor.*` or exact; commit lock file |

```xml
<!-- .NET — Directory.Packages.props -->
<PackageVersion Include="Microsoft.Azure.Cosmos" Version="[FETCHED]" />
<PackageVersion Include="Newtonsoft.Json" Version="[FETCHED]" />  <!-- ≥ 13.0.3 -->
```

```text
# Python — requirements.txt (compatible-release: allows same-minor patch updates)
azure-cosmos~=[MAJOR].[MINOR].0
```

```json
"@azure/cosmos": "~[MAJOR].[MINOR].0"
```

```xml
<!-- Java (Maven) -->
<dependency>
  <groupId>com.azure</groupId>
  <artifactId>azure-cosmos</artifactId>
  <version>[FETCHED]</version>
</dependency>
```

```groovy
// Java (Gradle)
implementation 'com.azure:azure-cosmos:[FETCHED]'
```

```
// go.mod
require github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos [FETCHED]
```

```toml
# Cargo.toml — tilde allows patch updates within declared minor
[dependencies]
azure_data_cosmos = "~[MAJOR].[MINOR]"
```

**Rule 3: .NET requires Newtonsoft.Json as an explicit direct dependency**

The .NET Cosmos DB SDK does not automatically resolve `Newtonsoft.Json` to a safe version. It must appear as an explicit entry and be validated separately alongside `Microsoft.Azure.Cosmos`:

```xml
<!-- ❌ Relying on transitive resolution — version is unpredictable -->
<!-- No Newtonsoft.Json entry in manifest -->

<!-- ✅ Explicit, validated alongside Microsoft.Azure.Cosmos -->
<PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
```

Never use 10.x — it has a known CVE. Use the NuGet registry URL from Rule 1 to check the current latest.

**Rule 4: Commit the lock file**

The manifest declares version intent; the lock file records the exact resolved dependency tree. A missing lock file means the resolved version is non-deterministic across machines and CI:

| Language | Lock file | Update command |
|---|---|---|
| .NET | `packages.lock.json` — enable with `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` | `dotnet restore` |
| Python | `poetry.lock` or `pip-compile`-generated `requirements.txt` | `poetry update` / `pip-compile` |
| Node.js | `package-lock.json` or `yarn.lock` — use `npm ci` in CI, not `npm install` | `npm install` |
| Java | Exact `<version>` in `pom.xml` acts as the pin; run `mvn versions:display-dependency-updates` | — |
| Go | `go.sum` — always commit alongside `go.mod` | `go get ...@latest` |
| Rust | `Cargo.lock` — commit for binaries; optional for libraries | `cargo update -p azure_data_cosmos` |

**Rule 5: Log the resolved version at startup**

Startup logging surfaces version drift in production without manual inspection:

```csharp
// .NET
var sdkVersion = typeof(CosmosClient).Assembly.GetName().Version;
logger.LogInformation("Microsoft.Azure.Cosmos version: {Version}", sdkVersion);
```

```python
# Python
import azure.cosmos
logging.info("azure-cosmos version: %s", azure.cosmos.__version__)
```

```typescript
// Node.js
const { version } = require("@azure/cosmos/package.json");
console.log(`@azure/cosmos version: ${version}`);
```

```java
// Java
String v = CosmosAsyncClient.class.getPackage().getImplementationVersion();
log.info("azure-cosmos version: {}", v);
```

```go
// Go — surface the resolved version via debug.ReadBuildInfo
import "runtime/debug"

if info, ok := debug.ReadBuildInfo(); ok {
    for _, dep := range info.Deps {
        if dep.Path == "github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos" {
            log.Printf("azcosmos version: %s", dep.Version)
        }
    }
}
```

```rust
// Rust — log your own crate version at compile time; use cargo-metadata for dependency versions
const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");
```

**Rule 6: Add Dependabot or Renovate to surface upgrades as reviewed PRs**

New minor releases should arrive as explicit pull requests, not silent installs:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: nuget
    directory: "/"
    schedule:
      interval: weekly
    groups:
      cosmos-sdk:
        patterns:
          - "Microsoft.Azure.Cosmos"
          - "Newtonsoft.Json"
```

Reference:
- [Microsoft.Azure.Cosmos on NuGet](https://www.nuget.org/packages/Microsoft.Azure.Cosmos)
- [azure-cosmos on PyPI](https://pypi.org/project/azure-cosmos/)
- [@azure/cosmos on npm](https://www.npmjs.com/package/@azure/cosmos)
- [com.azure:azure-cosmos on Maven Central](https://central.sonatype.com/artifact/com.azure/azure-cosmos)
- [Azure Cosmos DB SDK release notes (.NET)](https://learn.microsoft.com/azure/cosmos-db/nosql/sdk-dotnet-v3)
- [Azure Cosmos DB SDK release notes (Python)](https://learn.microsoft.com/azure/cosmos-db/nosql/sdk-python)
- [Azure Cosmos DB SDK release notes (Node.js)](https://learn.microsoft.com/azure/cosmos-db/nosql/sdk-nodejs)
- [Azure Cosmos DB SDK release notes (Java)](https://learn.microsoft.com/azure/cosmos-db/nosql/sdk-java-v4)
- [Go SDK (azcosmos) — pkg.go.dev](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos)
- [Go SDK source & releases — GitHub](https://github.com/Azure/azure-sdk-for-go/tree/main/sdk/data/azcosmos)
- [Rust SDK (azure_data_cosmos) — crates.io](https://crates.io/crates/azure_data_cosmos)
- [Rust SDK docs — docs.rs](https://docs.rs/azure_data_cosmos/latest/azure_data_cosmos/)
- [Azure Cosmos DB Spark connector — Maven Central](https://search.maven.org/search?q=g:com.azure.cosmos.spark)
- [Azure Cosmos DB Kafka connector — Maven Central](https://search.maven.org/search?q=g:com.azure.cosmos.kafka)
- [Newtonsoft.Json on NuGet](https://www.nuget.org/packages/Newtonsoft.Json)
- [NuGet Central Package Management](https://learn.microsoft.com/nuget/consume-packages/central-package-management)
