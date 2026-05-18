# syntax=docker/dockerfile:1.6
#
# ssh3 client image for the in-tree docker smoke-test stack.
#
# Build context is THIS directory (client/); the ssh3 source tree
# arrives as the named build context "ssh3-src" (see compose).

FROM golang:1.24-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY --from=ssh3-src . /src
ENV GO111MODULE=on CGO_ENABLED=0
# See server/Dockerfile for rationale on the build tag.
RUN go build -tags disable_password_auth -o /out/ssh3 ./cmd/ssh3

FROM alpine:3.20
RUN apk add --no-cache bash ca-certificates
COPY --from=build /out/ssh3 /usr/local/bin/ssh3
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
