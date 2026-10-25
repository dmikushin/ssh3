# OFFLINE_PREPARATION_NOT_DEPLOYABLE

This source-only checkpoint preserves the frozen v5 preparation artifacts. It is
NOT deployment approval, a complete cut-over tool, or evidence of production
handoff success. No Go443 service is changed by preparing this checkpoint.

## Included and tested scope

- Twelve host/container scripts and four strict-auth configuration templates.
- A request writer that publishes mode0400 before fsync and exclusive linking.
- An offline Python transport API and frozen observer; no network collector.
- The host receipt validator and minimal file/directory fsync C source.
- Six local interface controls, with synthetic management observations and an
  explicitly injected scratch directory/current uid (not production root).

Run the finite controls from this directory with:

```
python3 test-interface-v5.py
```

Check shell syntax with `bash -n` for each of the twelve `*-v5.sh` files.
The C helper must be built and staged separately; no binary is included.
`SOURCE.sha256` contains relative-path hashes for frozen source files.
The frozen generated scripts are included directly. No generator dependent on
missing earlier versions is included.

## Missing deployment prerequisites

- The real, independent Oracle management collector and its verified executable
  commands for process identity and complete socket snapshots.
- Secure network transport and receipt copyback, including fixed trusted root
  directory staging. The offline adapter is a Python API, not an SSH client.
- Fresh immutable runtime bindings: host boot ID, full container ID, namespace,
  process PID/starttime/executable hash/parent, complete original argv, and
  independently reviewed file/tool/identity ownership and modes.
- Root dispatcher, autonomous timer admission, staged helper/artifact manifests,
  complete container filesystem permissions and immutable public host-key pins.
- Identification and migration of unknown UDP64446 consumers.
- Actual caller-route migration for both provider3180 endpoints, migros and all
  reverse-forward consumers. HTTP health alone does not establish caller use.
- Complete acceptance, timer retirement and persistent container restart policy.

## Explicit limitations

The six controls exercise writer -> immutable local copies -> observer -> return
receipt -> host validator -> decision/callback. Synthetic observations are not
real socket facts. The fixture waits for its management thread before calling
the adapter; it does not exercise the full asynchronous host shell wait.
Shell syntax checks do not validate production behavior. Earlier primitive
fixtures do not certify these generated scripts as an integrated transaction.

No binaries, logs, private keys, public pin material, or runtime identity receipts
are included. Absolute operational paths in the templates are fixed staging
contracts, not discovered live identities. Do not execute against production
merely because a configuration template or marker file exists.
