# Docker smoke-test stack

A two-container docker-compose stack (ssh3 client + ssh3 server) on
an **isolated** docker bridge network — no host networking, no
published ports, no access to the host's internet.  Containers only
see each other.

This is the prod-leaning alternative to the in-tree
`local-integration-tests` target, which shells out `ip netns add`,
`iptables`, `sysctl` and `useradd` on the host.  Nothing here touches
host state outside of this working directory and docker's own
container runtime.

## Layout

```
integration_tests/docker/
├── bootstrap.sh        # one-time: generate TLS cert + ssh key in ./secrets
├── docker-compose.yml  # two services + an opt-in `tests` profile on internal bridge ssh3net
├── server/
│   ├── Dockerfile
│   └── entrypoint.sh   # creates the tunneluser inside the container
├── client/
│   ├── Dockerfile
│   └── entrypoint.sh   # reconnect loop + privkey perms
├── tests/
│   ├── Dockerfile
│   └── run-tests.sh    # echo + reverse-tcp smoke tests, exit 0 on PASS
└── secrets/            # gitignored; cert + ssh keys live here
```

## Prerequisites

- docker + docker compose v2 (with BuildKit, default since 23).
- The ssh3 source tree.  By default the compose file points at
  `../..` relative to itself, i.e. the ssh3 repo root.  Override with
  `SSH3_SRC=/path/to/other/ssh3 docker compose up --build` to build
  against a different checkout.

The stack does **not** need root on the host.  No `useradd`, no
`iptables`, no `sysctl`, no veth pairs.

## Run

From the repo root, the one-liner is:

```sh
make docker-smoke-tests
```

That generates the secrets, brings the server up, runs the test
runner, then tears everything down (containers, images, volumes).

Step-by-step from this directory:

```sh
./bootstrap.sh                                       # one-time: generate ./secrets/{cert,key,id_ed25519}
docker compose up -d --build server                  # start the server
docker compose --profile tests run --build --rm tests # run the smoke tests
docker compose down --rmi local -v                   # clean up
```

If you want to just bring the pair up interactively (no test runner):

```sh
docker compose up --build      # foreground; ctrl-c to stop
```

You should see:

```
ssh3-server  | ... Server started, listening on 0.0.0.0:4443/ssh3
ssh3-client  | ssh3 client: connecting to tunneluser@server:4443/ssh3
ssh3-client  | ... got response with 200 OK status code
ssh3-client  | ... opened new session channel
```

Reset:

```sh
docker compose down --rmi local -v    # remove containers + images + named volumes
rm -rf secrets                         # if you want to rotate keys
```

## Network isolation

The `ssh3net` bridge is declared with `internal: true` in
`docker-compose.yml`.  Per the docker docs that means:

> If set to `true`, the network is isolated from the host and from
> other networks.  Containers attached to it can only communicate
> with other containers on the same internal network.

So:

- containers can `dig server`, `nc server 4443` each other inside the bridge,
- the server's UDP/4443 is NOT reachable from the host,
- containers cannot reach `8.8.8.8`, the LAN, or any other docker network,
- the host's other services (sshd, web servers, etc.) are unaffected.

Image **build** still uses the default network (BuildKit needs it to
fetch go modules); once the image is built and started, only ssh3net
is attached.

If you want to publish the server's UDP port to the host for
debugging, do it in a separate file like `compose.override.yml` that
adds `ports: ["4443:4443/udp"]` and a non-internal network — keep the
default `docker-compose.yml` strictly isolated.

## Adding forwards

The client entrypoint passes whatever is in `SSH3_OPTIONS` through to
`ssh3` verbatim, mirroring how `jnovack/autossh` does `SSH_OPTIONS`.
Example for the autossh-replacement use case:

```yaml
services:
  client:
    environment:
      SSH3_OPTIONS: >-
        -reverse-tcp 0.0.0.0:2222@22/127.0.0.1
        -forward-tcp 8080/0.0.0.0@8080/127.0.0.1
```

## Knobs (client environment)

| var | default | meaning |
|---|---|---|
| `SSH3_REMOTE_USER` | required | user on the remote ssh3-server |
| `SSH3_REMOTE_HOST` | required | `host:port` of the remote |
| `SSH3_REMOTE_PATH` | `/ssh3` | URL path of the ssh3 endpoint |
| `SSH3_REMOTE_COMMAND` | `sleep infinity` | remote command keeping the tunnel alive |
| `SSH3_OPTIONS` | empty | extra args (forwards, reverse-forwards) |
| `SSH3_INSECURE` | unset | non-empty → add `-insecure` (self-signed cert) |
| `SSH3_ENABLE_MIGRATION` | unset | non-empty → add `-enable-migration` |
| `SSH3_RECONNECT_DELAY` | `5` | seconds between reconnect attempts |

## Knobs (server environment)

| var | default | meaning |
|---|---|---|
| `SSH3_BIND` | `0.0.0.0:4443` | bind address inside the container |
| `SSH3_URL_PATH` | `/ssh3` | URL path served |
| `SSH3_USER` | `tunneluser` | user the server setuids into when handling a session |
| `SSH3_USER_UID` | `1000` | uid of that user (inside the container) |

## Notes on the connection-migration flag

`-enable-migration` is on for the client by default in this compose
file.  Inside a pinned-IP docker network this won't migrate anywhere
(the client's source address never changes), but it does start the
coordinator goroutine and surfaces "netchange watcher" log lines in
client output — useful for confirming the build is the right one.
For a real migration drill you'd need either two networks attached
to the client and a route switch, or this stack run on a host where
the docker daemon's bridge IP changes, neither of which the default
compose intentionally arranges.

## What is intentionally NOT here

- No `--privileged`.
- No `network_mode: host`.
- No host port publishing in the default compose.
- No bind-mounts of host directories beyond the `./secrets` dir.
- No iptables/sysctl/useradd on the host.
- No proxy-jump path yet — proxy-jump migration is currently `PIt`
  (pending) in the Ginkgo suite while the test harness is reworked
  into a three-namespace topology.  This stack covers the direct
  client↔server case only.

## Relationship to the rest of the test suite

- `make test` — fast unit tests, no networking.
- `make integration-tests` — Ginkgo integration suite; assumes you've
  already prepared all the env vars (certs, users, privkeys).
- `make local-integration-tests` — same suite, but the harness
  script provisions everything on the host (sudo, useradd, sysctl,
  netns).  Heavy and intrusive; use on a throwaway VM.
- `make docker-smoke-tests` — **this stack.**  Low-risk, no host
  changes.  Validates the end-to-end SSH3 flow (echo + reverse-tcp)
  through an isolated docker bridge.  Preferred for a quick "did I
  break the build?" check on a workstation.
