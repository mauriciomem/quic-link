# Third-party notices

quic-link is distributed under the MIT License (see `LICENSE`).

Binaries built from this repository **statically embed** the third-party Go modules listed
below. Each carries its own licence, and every one of those licences requires its notice to
travel with the software it is embedded in. **This file is that notice, and it must ship with
any release artifact** — not only with the source tree — because a compiled binary containing a
library's code is a "substantial portion" of that library for licensing purposes.

## How to regenerate this list

```bash
go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./cmd/quic-link | sort -u
# then read the LICENSE / LICENCE / COPYING file in each module's directory under $(go env GOMODCACHE)
```

Re-run it whenever a module is **added to or removed from** the build. A dependency added
without updating this file is a licence violation in any shipped binary, not merely an
administrative omission.

**Versions are deliberately not recorded here.** The obligation attaches to a module, not to a
particular release of one, so a version column would add no legal precision while making every
routine dependency bump falsify this file. Which version of each module a given binary contains
is recorded in the binary itself and can be read back with `go version -m quic-link` — a source
that cannot drift from the artifact, unlike a hand-maintained table.

---

## MIT

Permission notice and copyright must be reproduced.

| Module |
|---|
| `github.com/quic-go/quic-go` |
| `github.com/fxamacker/cbor/v2` |
| `github.com/pelletier/go-toml/v2` |
| `github.com/x448/float16` |

Full licence text: `LICENSE` in each module's directory in the Go module cache.

## BSD-3-Clause

Copyright notice, conditions, and disclaimer must be reproduced. The third clause forbids using
the copyright holder's name to endorse derived products without permission.

| Module |
|---|
| `golang.org/x/net` |
| `golang.org/x/sys` |
| `golang.org/x/crypto` |
| `golang.org/x/text` |
| `google.golang.org/protobuf` |
| `github.com/spf13/pflag` |

The `golang.org/x/*` and `google.golang.org/protobuf` modules are Copyright (c) The Go Authors.

## Apache-2.0

Requires the licence text, retention of attribution notices, and a statement of changes if the
files were modified. **quic-link modifies none of these modules.**

| Module |
|---|
| `google.golang.org/grpc` |
| `google.golang.org/genproto/googleapis/rpc` |
| `github.com/spf13/cobra` |
| `github.com/inconshreveable/mousetrap` |

> ⚠️ **Apache-2.0 §4(d) obligation.** Where a distributed module includes a `NOTICE` file, its
> contents **must be reproduced** in derivative distributions. Of the modules above, only
> `google.golang.org/grpc` ships one, and its contents are reproduced below. Check for a
> `NOTICE` file whenever an Apache-2.0 module is added to the build:
>
> ```bash
> find "$(go env GOMODCACHE)/<module>@<version>" -maxdepth 1 -iname 'NOTICE*'
> ```

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
