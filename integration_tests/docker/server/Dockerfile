# syntax=docker/dockerfile:1.6
#
# ssh3 server image for the in-tree docker smoke-test stack.
#
# Build context is THIS directory (server/) - so entrypoint.sh is
# directly addressable.  The ssh3 source tree comes in as a named
# build context (additional_contexts.ssh3-src in compose), which
# lets us build against the local checkout (or an overridden fork)
# without copying go sources into this directory.

FROM golang:1.24-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY --from=ssh3-src . /src
ENV GO111MODULE=on CGO_ENABLED=0
# `disable_password_auth` build tag picks the unix_util fallback
# (non_password_auth_user.go) that doesn't need libcrypt / cgo /
# /etc/shadow.  We authenticate via ssh3's authorized_identities
# (pubkey) anyway, so password auth would be unused even if we
# pulled it in.
RUN go build -tags disable_password_auth -o /out/ssh3-server ./cmd/ssh3-server

FROM alpine:3.20
RUN apk add --no-cache \
      bash \
      shadow \
      openssl \
      ca-certificates
COPY --from=build /out/ssh3-server /usr/local/bin/ssh3-server
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 4443/udp
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
