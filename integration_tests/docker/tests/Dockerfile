# syntax=docker/dockerfile:1.6
#
# Test runner image: ssh3 client + iproute2 + curl + socat for the
# smoke tests in run-tests.sh.

FROM golang:1.24-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY --from=ssh3-src . /src
ENV GO111MODULE=on CGO_ENABLED=0
RUN go build -tags disable_password_auth -o /out/ssh3 ./cmd/ssh3

FROM alpine:3.20
RUN apk add --no-cache bash ca-certificates iproute2 curl socat
COPY --from=build /out/ssh3 /usr/local/bin/ssh3
COPY run-tests.sh /usr/local/bin/run-tests.sh
RUN chmod +x /usr/local/bin/run-tests.sh
ENTRYPOINT ["/usr/local/bin/run-tests.sh"]
