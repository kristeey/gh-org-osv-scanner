# gh-org-osv-scanner

Scans all repositories in a GitHub organization for vulnerabilities using the [OSV Scanner](https://github.com/google/osv-scanner) library and writes a combined report to `scan-results.txt`.

## How it works

1. **List repos** — fetches all repositories in the target org via the GitHub REST API (paginated, 100 per page).
2. **Clone → scan → delete** — for each repo in sequence:
   - shallow-clones it (`depth=1`) into a temp directory using [go-git](https://github.com/go-git/go-git)
   - scans the cloned directory recursively with `osvscanner.DoScan`
   - removes the clone before moving to the next repo
3. **Write results** — findings are written to `scan-results.txt` as each repo finishes, grouped by repository. A summary with totals is appended at the end.
4. **(Optionally) Send to Slack** — uploads `scan-results.txt` to a Slack channel using a bot token, then deletes the local file.

Processing is intentionally sequential to keep memory and disk usage low.

## Usage

```sh
# Public org (no auth)
go run . <github-org>

# With token — required for private repos, also avoids API rate limits
GITHUB_TOKEN=ghp_xxx go run . <github-org>

# Custom plugin list from file
GITHUB_TOKEN=ghp_xxx go run . <github-org> --plugins plugins.txt

# Skip specific repos
GITHUB_TOKEN=ghp_xxx go run . <github-org> --ignore-repos ignore.txt

# Upload scan-results.txt to a Slack channel after scanning
GITHUB_TOKEN=ghp_xxx SLACK_TOKEN=xoxb-xxx go run . <github-org> --slack-channel C1234567890

# Suppress osv-scanner verbose output (default is warn)
go run . <github-org> --log-level error

# Show all osv-scanner output
go run . <github-org> --log-level debug
```

### Slack setup

After scanning, the tool uploads `scan-results.txt` to a Slack channel as a file attachment with an inline summary comment. The local file is deleted after a successful upload.

Requirements:
- A Slack app with a bot token (`xoxb-...`) set in the `SLACK_TOKEN` env var
- Bot token scope: `files:write`
- The bot must be invited to the target channel (`/invite @your-bot`)
- Pass the channel ID (not name) via `--slack-channel`

The upload uses the [Slack external upload API](https://docs.slack.dev/messaging/working-with-files/#upload) (`files.getUploadURLExternal` → PUT → `files.completeUploadExternal`).

## Plugins

By default the scanner uses the `lockfile` preset (all lock file / manifest extractors) and the `sbom` preset, with Java disabled. You can override this by passing a file with `--plugins`.

**Enabled by default:**

| Plugin | What it scans |
|---|---|
| `lockfile` preset | All lock file / manifest extractors across every ecosystem |
| → `go/gomod` | go.mod / go.sum |
| → `javascript/packagelockjson` | package-lock.json, npm-shrinkwrap.json |
| → `javascript/yarnlock` | yarn.lock |
| → `javascript/pnpmlock` | pnpm-lock.yaml |
| → `javascript/bunlock` | bun.lockb |
| → `dotnet/depsjson` | *.deps.json |
| → `dotnet/packagesconfig` | packages.config |
| → `dotnet/packageslockjson` | packages.lock.json |
| → `dotnet/nugetcpm` | Directory.Packages.props |
| → `dotnet/csproj` | *.csproj |
| → `python/requirements` | requirements*.txt |
| → `python/pipfilelock` | Pipfile.lock |
| → `python/poetrylock` | poetry.lock |
| → `python/pdmlock` | pdm.lock |
| → `python/uvlock` | uv.lock |
| → `python/pylock` | pyproject.toml (PEP 751) |
| → `ruby/gemfilelock` | Gemfile.lock |
| → `rust/cargolock` | Cargo.lock |
| → `php/composerlock` | composer.lock |
| `sbom` preset | SPDX / CycloneDX SBOM files (`sbom/spdx`, `sbom/cdx`) |

**Disabled by default** (present in `lockfile` preset but excluded):

| Plugin | Reason |
|---|---|
| `java/pomxml` | Triggers network calls to Maven registries |
| `java/gradlelockfile` | Java not in scope |
| `java/gradleverificationmetadataxml` | Java not in scope |

> **Note:** GitHub Actions workflow scanning (`.github/workflows/*.yml`) and Container images referenced in dockerfiles/k8s manifests is not supported atm.

### plugins.txt format

One plugin name per line. Lines starting with `#` and blank lines are ignored.
Prefix a name with `-` to disable it (useful for trimming a preset).

```
# Presets
lockfile   # all lock file / manifest extractors across every ecosystem
sbom       # SPDX and CycloneDX files

# Disable specific extractors from the presets above
-java/pomxml
-ruby/gemfilelock
-rust/cargolock
```

**Valid preset names:**

| Preset | Covers |
|---|---|
| `lockfile` | All lock file / manifest extractors across every ecosystem |
| `artifact` | Compiled artifacts — Go binaries, .whl, JARs, node_modules, etc. |
| `sbom` | SPDX and CycloneDX files |
| `directory` | Git repo metadata, vendored dependencies |
| `transitive` | Transitive dependency resolution (makes network calls) |

### Finding available plugin names

Individual extractor names come from [osv-scalibr](https://github.com/google/osv-scalibr). Each extractor package declares its name as `const Name = "category/name"` at the top of its main `.go` file. Browse by area:

- Lock files / manifests: [`extractor/filesystem/language/`](https://github.com/google/osv-scalibr/tree/main/extractor/filesystem/language)
- Secret scanning: [`extractor/filesystem/secrets/`](https://github.com/google/osv-scalibr/tree/main/extractor/filesystem/secrets)

The full map of individual names is in [`extractor/filesystem/list/list.go`](https://github.com/google/osv-scalibr/blob/main/extractor/filesystem/list/list.go).

Individual names that work as `PluginsEnabled` entries (exact `const Name` values):

| Ecosystem | Plugin names |
|---|---|
| Go | `go/gomod`, `go/binary` |
| JavaScript | `javascript/packagelockjson`, `javascript/yarnlock`, `javascript/pnpmlock`, `javascript/bunlock` |
| .NET | `dotnet/depsjson`, `dotnet/packagesconfig`, `dotnet/packageslockjson`, `dotnet/nugetcpm`, `dotnet/csproj` |
| Python | `python/requirements`, `python/pipfilelock`, `python/poetrylock`, `python/pdmlock`, `python/uvlock`, `python/pylock`, `python/wheelegg` |
| Java | `java/pomxml`, `java/gradlelockfile`, `java/gradleverificationmetadataxml` |
| Ruby | `ruby/gemfilelock` |
| Rust | `rust/cargolock`, `rust/cargoauditable` |
| PHP | `php/composerlock` |
| SBOM | `sbom/spdx`, `sbom/cdx` |

> **Note:** Ecosystem shorthand names like `go`, `python`, `dotnet` are **not** valid as plugin names — they exist only inside osv-scalibr's internal map. Use the `lockfile` preset with `-` exclusions instead.

## Output format

```
OSV Scanner Results
Org:            my-org
Scan time:      2026-04-25T10:00:00Z
Repos scanned:  42
Repos ignored:  3

Ignored repos:
  - archived-repo
  - test-sandbox
  - legacy-monolith
================================================================================

## repo-name
╭─────────────────────────────────────┬──────┬───────────┬───────────────┬─────────┬───────────────┬──────────────────╮
│ OSV URL                             │ CVSS │ ECOSYSTEM │ PACKAGE       │ VERSION │ FIXED VERSION │ SOURCE           │
├─────────────────────────────────────┼──────┼───────────┼───────────────┼─────────┼───────────────┼──────────────────┤
│ https://osv.dev/GHSA-xxxx-xxxx-xxxx │ 7.5  │ Go        │ some-package  │ 1.2.3   │ 1.2.4         │ my-org/repo/go.sum │
╰─────────────────────────────────────┴──────┴───────────┴───────────────┴─────────┴───────────────┴──────────────────╯

## another-repo
  No package manifests found

================================================================================
SUMMARY
Repos scanned:              42
Repos with vulnerabilities: 3
Total vulnerabilities:      7
```

Source paths are shown relative to the org root (e.g. `my-org/repo-name/go.sum`) rather than as local temp directory paths.

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/google/osv-scanner` | Vulnerability scanning |
| `github.com/go-git/go-git` | Cloning repositories |
| `github.com/google/go-github` | GitHub API client |
