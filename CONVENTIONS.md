# Shared conventions

`mailcow-watchdog` and `mailcow-dockerapi` are both drop-in replacements for a
mailcow service. They are separate modules with separate release cycles, but they
are read, operated and debugged as a pair, so they follow one house style.

There is deliberately **no shared module**. The cross-cutting files listed under
[Shared files](#shared-files) are kept byte-near identical in both repositories
instead; each of them names its origin in the header comment. The trade is
explicit: no third repository to release, at the price of copying a change into
the sibling repository by hand.

This file is one of those shared files. Change it in one repository, then copy it
to the other.

---

## Language

English, everywhere: comments, doc comments, error strings, sentinel messages,
`README.md`, `DEVIATIONS.md`, `Makefile` help text, Dockerfile comments, workflow
files, commit messages.

The originals being replaced are English, mailcow upstream is English, and error
strings end up in operator-facing logs that are grepped against upstream issues.

Identifiers use the vocabulary of the domain, not of the original's
implementation: `primary`/`replica` rather than `master`/`slave`, except where a
wire format or a server response dictates the older spelling. Those exceptions
carry a comment saying so.

---

## Repository layout

```
cmd/<binary>/main.go      config, logger, wiring, signals, shutdown — nothing else
internal/config/          config.go (types + validate) and load.go (env -> Config)
internal/logging/         slog handler factory
internal/obs/             /metrics, /healthz, /readyz and Readiness
internal/store/           Redis behind an interface
internal/<domain>/...     the actual service
original/                 the replaced implementation, for reference (gitignored)
CONVENTIONS.md            this file
DEVIATIONS.md             numbered differences from the original
README.md                 what it is, the interface, configuration, development
.golangci.yml
.dockerignore
.forgejo/workflows/ci.yml
.forgejo/workflows/release.yml
```

Every package has a package comment that says what the package is for and, where
it matters, which part of the original it replaces.

---

## Configuration

The environment is the only configuration source. Variable names come from
mailcow and are never renamed; additions are prefixed with the service name.

- `type Lookup func(key string) (string, bool)`, `EnvLookup` for production, a
  map for tests. Nothing outside `load.go` reads `os.Getenv`.
- `Load(look Lookup) (*Config, error)`.
- Parse errors accumulate in the `env` helper (`str`, `int`, `duration`, and
  whatever else a service needs) so a misconfigured deployment learns about every
  bad variable at once.
- Validation is a method, `(*Config) validate() error`, called last. It rejects
  what would otherwise fail silently or in a loop.
- `Config` groups its fields into sub-structs per concern (`Redis`, `Docker`,
  `Log`, `Obs`, ...). Derived values (DSNs, URLs, endpoints) are computed once,
  in `Load` or on the sub-struct, never re-assembled by consumers.
- Defaults are named constants with a comment explaining the number.

## Logging

`log/slog`, built by `logging.New(w io.Writer, opts logging.Options) *slog.Logger`
and installed with `slog.SetDefault`. `logging.Options` mirrors `config.Log` field
for field, so `main` converts one into the other — `logging.New(os.Stdout,
logging.Options(cfg.Log))` — and the logging package does not import the
configuration package. Formats: `json`, `text`, plus a service-specific
compatibility format where the replaced implementation had one; that format is
then the default, because a drop-in replacement should not change what an
operator's log processing sees.

- `LOG_LEVEL` = `debug|info|warn|error`, `LOG_FORMAT` = the formats above.
- The error attribute is `err`, never `error`.
- Struct fields and parameters holding a logger are called `Log`.
- Packages scope their logger with `log.With("component", "<package>.<thing>")`.
- A `nil` logger passed into a constructor falls back to `slog.Default()`.

## Observability

Both services expose the same three endpoints from `internal/obs`, on
`<SERVICE>_METRICS_LISTEN` (empty disables the server):

- `GET /metrics` — Prometheus, from a `prometheus.Registry` built in `main`.
- `GET /healthz` — liveness. It must not touch Redis, MariaDB or Docker: a
  dependency outage must not have the orchestrator kill the process that reports
  on it.
- `GET /readyz` — readiness, negative until every connection the service cannot
  work without is up.

Metric names are `<service>_<subsystem>_<unit>` with a `_total` suffix on
counters. A registry is passed in, never `prometheus.DefaultRegisterer`.

## Program lifecycle

`main` is `func main() { if err := run(); err != nil { ... os.Exit(1) } }`, and
`run` follows the same sequence in both services:

1. `config.Load(config.EnvLookup)`
2. `logging.New`, `slog.SetDefault`, one startup line with the version
3. `signal.NotifyContext` for SIGINT and SIGTERM
4. registry, metrics, `obs.Server` started in a goroutine
5. `connect` — every external connection, with a LIFO `cleanup` closure
6. `build` — wiring, no I/O
7. `readiness.SetReady(true)`
8. the service loop, then shutdown bounded by a named timeout constant

`version` is a package-level `var version = "dev"`, set via
`-ldflags "-X main.version=..."`.

## Package and API conventions

- Constructors are `New(opts Options) *T`. The options struct is called
  `Options` — not `Config`, which is reserved for the configuration package. No
  `NewRedis`-style suffixes: the package name already says it.
- Time is injectable: `Now func() time.Time` in `Options`, `nil` meaning
  `time.Now`. Tests pin it.
- Every external dependency sits behind an interface declared in the package
  that *consumes* it, holding only the methods that package actually calls.
- Fakes live in `<package>test/fake.go` (`storetest`, `dockertest`), record the
  calls they receive, and are never linked into the binary.
- Exported identifiers whose shape is dictated by an external consumer (Redis
  record layouts, HTTP response bodies, registry keys) say so in a comment.

## Errors

- Wrap with a lower-case description of the operation plus `%w`:
  `fmt.Errorf("opening the mailcow database: %w", err)`. Not `"db: %w"`.
- Sentinels are `ErrSomething` in the package where the condition arises,
  compared with `errors.Is`.
- Errors that are a normal state ("key not set yet", "container not found") are
  reported through a boolean or a typed result, not as an error.
- `context.Context` is the first parameter of anything that does I/O.

## Tests

- `go test -race` is the baseline; the default `make` target runs it.
- Table-driven where the cases are data, explicit where they are behaviour.
- No test needs a mailcow stack, a Docker daemon or the network. Tests that do
  are behind the `integration` build tag and a separate make target.
- Fake servers on loopback stand in for protocol peers; `miniredis` stands in for
  Redis.
- `cmd/<binary>` has a test too — the wiring is where a rename silently breaks.

---

## Build

`make` is the only build interface; CI configs are thin wrappers around it. The
target set is identical in both repositories:

| Target | Meaning |
|---|---|
| `help` | list the targets |
| `build` | static binary into `bin/` |
| `test` | `go test -race -count=1 ./...` |
| `cover` | coverage profile plus the total |
| `bench` | benchmarks with allocation stats |
| `fmt` | fail if anything is not gofmt-clean |
| `vet` | `go vet ./...` |
| `lint` | `golangci-lint run ./...` |
| `vuln` | `govulncheck ./...` |
| `sec` | `lint` + `vuln` |
| `tidy` | `go mod tidy` + `go mod verify` |
| `ci` | `fmt vet lint vuln test build` |
| `image` | container image |
| `release` | cross-compiled static binaries into `dist/` |
| `clean` | remove build artefacts |

Service-specific targets are additions, never replacements (`fuzz`, `compare`,
`test-integration`).

`fmt` checks and fails — it does not rewrite. `.DEFAULT_GOAL := build`.
`VERSION ?= $(shell git describe --tags --always --dirty)`. Builds are
`CGO_ENABLED=0 -trimpath -ldflags '-s -w -X main.version=$(VERSION)'`.

## Go version

Both modules pin the same patch version in `go.mod`, and both Dockerfiles pin the
builder image to exactly that version. The patch level is chosen so that
`govulncheck` reports no standard-library advisories; the reason is a comment in
`go.mod`.

## Container image

Multi-stage: `golang:<go.mod version>-alpine` to build,
`gcr.io/distroless/static-debian13:latest` to run. Distroless carries the CA
bundle and the timezone database and has no shell and no package manager.

- `COPY go.mod go.sum` and `go mod download` before the source, so the
  dependency layer survives source edits.
- `ARG VERSION=dev`, passed into the `-X main.version` ldflag.
- Three OCI labels: `title`, `description`, `source`.
- A `.dockerignore` that keeps the build context to what the compiler needs.
- Whether the image runs as root is a decision with a comment naming the mounts
  that force it.

## CI

`.forgejo/workflows/ci.yml` on pushes to `main` and on pull requests:
checkout, `setup-go` with `go-version-file: go.mod`, then `fmt`, `vet`,
`golangci-lint` (pinned version), `govulncheck`, `test -race`, `build` — each
step a `make` call.

`.forgejo/workflows/release.yml` on `v*` tags: `make release VERSION=<tag>`,
`sha256sum` over `dist/`, upload as release assets.

Linters beyond the golangci-lint defaults: `gosec`, `bodyclose`, `misspell`.
`errcheck` exclusions are limited to writes to stdout/stderr/`ResponseWriter` and
deferred `Close` on things already finished with, each with a reason in the
config.

---

## Shared files

Kept identical in both repositories, modulo the binary name and service-specific
metrics:

- `CONVENTIONS.md`
- `internal/config/load.go` — the `env` helper and `Lookup` (the `Config` types
  themselves are service-specific)
- `internal/logging/logging.go` — the factory and `Level` (a compatibility handler
  lives in its own file and is not shared)
- `internal/obs/obs.go` and `internal/obs/obs_test.go` — byte-identical
- `.golangci.yml`
- `.forgejo/workflows/ci.yml`, `.forgejo/workflows/release.yml`
- the `Makefile` target set, its help mechanism and its flags
