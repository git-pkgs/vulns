# vulns

Go library for fetching vulnerability data from multiple sources using Package URLs (PURLs) as the primary identifier.

## Installation

```
go get github.com/git-pkgs/vulns
```

## Usage

Query vulnerabilities for a package:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/git-pkgs/purl"
    "github.com/git-pkgs/vulns"
    "github.com/git-pkgs/vulns/osv"
)

func main() {
    ctx := context.Background()
    source := osv.New()

    p := purl.MakePURL("npm", "lodash", "4.17.20")

    results, err := source.Query(ctx, p)
    if err != nil {
        log.Fatal(err)
    }

    for _, v := range results {
        fmt.Printf("%s: %s (severity: %s)\n", v.ID, v.Summary, v.SeverityLevel())
        if fixed := v.FixedVersion("npm", "lodash"); fixed != "" {
            fmt.Printf("  Fixed in: %s\n", fixed)
        }
    }
}
```

## Sources

### OSV (Open Source Vulnerabilities)

Free, public API from Google. No authentication required. Supports batch queries up to 1000 packages.

```go
import "github.com/git-pkgs/vulns/osv"

source := osv.New()

// Batch query
results, err := source.QueryBatch(ctx, []*purl.PURL{p1, p2, p3})
```

### deps.dev

Free API from Google with no authentication. Covers npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems. Supports batch queries up to 5000 packages.

```go
import "github.com/git-pkgs/vulns/depsdev"

source := depsdev.New()
```

### GitHub Security Advisories (GHSA)

Free public API. Authentication optional but recommended to avoid rate limits.

```go
import "github.com/git-pkgs/vulns/ghsa"

source := ghsa.New()

// With authentication for higher rate limits:
source := ghsa.New(ghsa.WithToken("ghp_xxxx"))
```

### NVD (National Vulnerability Database)

NIST's CVE database. Free but rate-limited. API key recommended.

- Without key: 5 requests per 30 seconds
- With key: 50 requests per 30 seconds

```go
import "github.com/git-pkgs/vulns/nvd"

source := nvd.New()

// With API key for higher rate limits:
source := nvd.New(nvd.WithAPIKey("your-api-key"))
```

Note: NVD uses CVE/CPE identifiers, so PURL-to-package matching is approximate.

### Grype Database

Local SQLite database from Anchore. Updated every few hours at grype.anchore.io. No network requests after initial download.

```go
import "github.com/git-pkgs/vulns/grypedb"

// Auto-download if missing
source, err := grypedb.New("/path/to/cache", grypedb.WithAutoDownload())
if err != nil {
    log.Fatal(err)
}
defer source.Close()

// Or download manually
dbPath, err := grypedb.Download(ctx, "/path/to/cache")
source, err := grypedb.New(dbPath)
```

### VulnCheck

Commercial API with native PURL support. Requires authentication.

```go
import "github.com/git-pkgs/vulns/vulncheck"

source := vulncheck.New(vulncheck.WithToken("your-api-token"))
```

### Vulnerability-Lookup

Free, public API from vulnerability-lookup.org. Queries by vendor/product, so PURL mapping may be approximate.

```go
import "github.com/git-pkgs/vulns/vl"

source := vl.New()
```

## Data Model

All sources return vulnerabilities in OSV format:

```go
type Vulnerability struct {
    ID        string
    Summary   string
    Details   string
    Aliases   []string     // Other IDs (CVE, GHSA, etc.)
    Published time.Time
    Modified  time.Time
    Severity  []Severity
    Affected  []Affected
    References []Reference
}
```

## Working with CVSS

The library includes a CVSS parser supporting v2.0, v3.0, v3.1, and v4.0:

```go
// Get severity level
level := vuln.SeverityLevel() // "critical", "high", "medium", "low", "unknown"

// Get numeric score
score := vuln.CVSSScore() // 0.0-10.0, or -1 if unavailable

// Get full CVSS details
cvss := vuln.CVSS()
if cvss != nil {
    fmt.Printf("CVSS %s: %.1f (%s)\n", cvss.Version, cvss.Score, cvss.Level)
}

// Parse a CVSS vector directly
cvss, err := vulns.ParseCVSS("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
```

## Version Matching

Check if a specific version is affected:

```go
if vuln.IsVersionAffected("npm", "lodash", "4.17.20") {
    fmt.Println("Version is vulnerable")
}

if fixed := vuln.FixedVersion("npm", "lodash"); fixed != "" {
    fmt.Printf("Upgrade to %s\n", fixed)
}
```

## Source Interface

All sources implement the same interface:

```go
type Source interface {
    Name() string
    Query(ctx context.Context, p *purl.PURL) ([]Vulnerability, error)
    QueryBatch(ctx context.Context, purls []*purl.PURL) ([][]Vulnerability, error)
    Get(ctx context.Context, id string) (*Vulnerability, error)
}
```

## Supported Ecosystems

| Ecosystem | OSV | deps.dev | GHSA | NVD | Grype | VulnCheck | vl |
|-----------|-----|----------|------|-----|-------|-----------|-----|
| npm | yes | yes | yes | yes | yes | yes | yes |
| PyPI | yes | yes | yes | yes | yes | yes | yes |
| RubyGems | yes | yes | yes | yes | yes | yes | yes |
| crates.io | yes | yes | yes | yes | yes | yes | yes |
| Go | yes | yes | yes | yes | yes | yes | yes |
| Maven | yes | yes | yes | yes | yes | yes | yes |
| NuGet | yes | yes | yes | yes | yes | yes | yes |
| Packagist | yes | - | yes | yes | yes | yes | yes |
| Hex | yes | - | yes | - | yes | yes | - |
| Pub | yes | - | yes | - | yes | yes | - |

## License

MIT
