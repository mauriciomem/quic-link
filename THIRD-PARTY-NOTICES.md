# Third-party notices

quic-link is distributed under the MIT License (see `LICENSE`).

Binaries built from this repository **statically embed** the third-party Go modules listed
below. Each carries its own licence, and every one of those licences requires its notice to
travel with the software it is embedded in. **This file is that notice, and it must ship with
any release artifact** — not only with the source tree — because a compiled binary containing a
library's code is a "substantial portion" of that library for licensing purposes.

## How to regenerate this list

```bash
go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./... | sort -u
# then read the LICENSE / LICENCE / COPYING file in each module's directory under $(go env GOMODCACHE)
```

Re-run it whenever `go.mod` changes. A dependency added without updating this file is a licence
violation in any shipped binary, not merely an administrative omission.

---

## MIT

Permission notice and copyright must be reproduced.

| Module | Version |
|---|---|
| `github.com/quic-go/quic-go` | v0.60.0 |
| `github.com/fxamacker/cbor/v2` | v2.9.2 |
| `github.com/pelletier/go-toml/v2` | v2.4.3 |
| `github.com/x448/float16` | v0.8.4 |

Full licence text: `LICENSE` in each module's directory in the Go module cache.

## BSD-3-Clause

Copyright notice, conditions, and disclaimer must be reproduced. The third clause forbids using
the copyright holder's name to endorse derived products without permission.

| Module | Version |
|---|---|
| `golang.org/x/net` | v0.55.0 |
| `golang.org/x/sys` | v0.45.0 |
| `golang.org/x/crypto` | v0.51.0 |
| `golang.org/x/text` | v0.37.0 |
| `google.golang.org/protobuf` | v1.36.11 |
| `github.com/spf13/pflag` | v1.0.9 |

The `golang.org/x/*` and `google.golang.org/protobuf` modules are Copyright (c) The Go Authors.

## Apache-2.0

Requires the licence text, retention of attribution notices, and a statement of changes if the
files were modified. **quic-link modifies none of these modules.**

| Module | Version | Ships a `NOTICE` file? |
|---|---|---|
| `google.golang.org/grpc` | v1.82.0 | **Yes — `NOTICE.txt`** |
| `github.com/spf13/cobra` | v1.10.2 | No |
| `github.com/inconshreveable/mousetrap` | v1.1.0 | No |

> ⚠️ **Apache-2.0 §4(d) obligation.** Where a distributed module includes a `NOTICE` file, its
> contents **must be reproduced** in derivative distributions. `google.golang.org/grpc` ships
> `NOTICE.txt`, so its contents are reproduced below.

### `google.golang.org/grpc` — NOTICE.txt

```
Copyright 2014 gRPC authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## Note on scope

This file covers modules **compiled into the binary** (`go list -deps`), which is the set the
licences actually attach to. It deliberately does not enumerate the wider module graph
(`go list -m all`), which includes modules used only for testing or tooling and never shipped.

## Changelog

- 2026-08-13: Created. The obligation is **pre-existing** — it arrived with the first shipped
  binary embedding these libraries, not with any later decision — and had not previously been
  met. Verified against the build closure rather than the `go.mod` require block, which is the
  correct set. One correction made in the process: `github.com/spf13/cobra` is **Apache-2.0**,
  not MIT as previously assumed, which brings the §4(d) `NOTICE` obligation into scope and
  surfaced `google.golang.org/grpc`'s `NOTICE.txt`.
