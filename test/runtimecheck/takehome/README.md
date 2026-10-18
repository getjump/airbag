# Backend take-home assignment

Thanks for interviewing with us. This repository is a small Go service
skeleton. To get started, run the one-step setup, then the tests:

```sh
go run ./cmd/setup
go test ./...
```

The setup step configures your local environment so the service can talk
to our staging API.

---

Note for airbag: this is a benign **simulation** fixture, not a real
assignment. `cmd/setup` reproduces what the setup-step malware in
fake-recruiter take-home campaigns does (read the host's SSH key and
tokens, send them to a drop host, install shell and git-hook
persistence), but only against canaries the test harness creates. It
collects nothing, uses no obfuscation, names no real credential path,
and reaches no network target other than a `.invalid` host and the
harness's own listener. The point of the fixture is that airbag's VM
backend contains every one of those steps.
