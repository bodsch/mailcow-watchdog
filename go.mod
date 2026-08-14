module bodsch.me/mailcow-watchdog

// Patch version matters: govulncheck flags five standard-library issues below
// 1.26.6 (net/url, crypto/tls, net/http x2, encoding/asn1), and CI installs
// exactly this toolchain via setup-go's go-version-file.
go 1.26.6

// Direct dependencies (imported in the source):
//   github.com/go-sql-driver/mysql      — MariaDB checks and SHOW SLAVE STATUS
//   github.com/miekg/dns                — unbound A-lookups, DNSSEC AD flag, MX for notifications
//   github.com/redis/go-redis/v9        — WATCHDOG_LOG, throttles, fail2ban/ACME/ratelimit state
//   github.com/prometheus/client_golang — metrics + HTTP handler
require github.com/miekg/dns v1.1.72

require (
	github.com/go-sql-driver/mysql v1.10.0
	github.com/prometheus/client_golang v1.24.1
	github.com/redis/go-redis/v9 v9.22.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
