# mailcow watchdog
#
# The shell watchdog needed an Alpine base with roughly twenty-five packages —
# the Nagios plugin collection, bind-tools, mariadb-client, redis, jq, whois, a
# Perl stack and an smtp-cli fetched from GitHub at build time over an unpinned
# URL. All of that is now in the binary, so the runtime image carries the binary,
# a CA bundle and the timezone database, and nothing else.
#
# Practical consequences: no shell in the image, no package CVEs to chase, and
# nothing to execute if a probe response were ever mishandled.

FROM golang:1.26.6-alpine AS build

WORKDIR /src

# Copy the manifests first so the dependency layer is cached across source edits.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# VERSION is the only way the version reaches the binary: `git describe` cannot
# run here, because .dockerignore keeps .git out of the build context. The CI
# passes the tag; a plain `docker build` yields "dev", which is honest.
ARG VERSION=dev
ENV CGO_ENABLED=0 GOOS=linux

# ${VERSION:-dev} guards against an explicitly empty --build-arg VERSION=, which
# would stamp an empty string and read as a broken build rather than an unstamped
# one.
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION:-dev}" \
      -o /out/watchdog ./cmd/watchdog


# The runtime stage carries no shell and no package manager.
FROM gcr.io/distroless/static-debian13:latest

LABEL org.opencontainers.image.title="mailcow-watchdog" \
      org.opencontainers.image.description="Monitors a mailcow installation and restarts unresponsive containers" \
      org.opencontainers.image.source="https://github.com/mailcow/mailcow-dockerized"

COPY --from=build /out/watchdog /watchdog

# The image runs as root, as watchdog.sh did, because of the bind mounts it
# reads: postfix's deferred queue is mode 0700 and owned by the postfix user, and
# the shared mysqld and rspamd sockets are not world-accessible either. Switching
# to the :nonroot tag is possible, but only together with matching group
# ownership on those three mounts — otherwise the mailq, mysql and rspamd checks
# would fail permanently for a reason that has nothing to do with the services.

EXPOSE 9393

ENTRYPOINT ["/watchdog"]
