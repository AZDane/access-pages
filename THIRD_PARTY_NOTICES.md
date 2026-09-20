# Third-party notices

This distribution includes qURL 2.6.0 (embedded Connector 0.14.0),
the Access Pages Go guest endpoint, the Go standard library, Python 3.12,
the local QR code library, and base-image operating-system packages.

The complete license text shipped in the qURL release archive is
`third_party_licenses/qurl-2.6.0-LICENSE` (MIT). The Go 1.26.6 and
1.26.8 standard-library/toolchain license text is
`third_party_licenses/Go-1.26.6-and-1.26.8-LICENSE` (BSD-3-Clause).
The two Go versions have byte-identical license files. The qURL binary
uses Go 1.26.6; our guest endpoint uses Go 1.26.8.

The qURL release SPDX inventories for both shipped architectures are in
`third_party_licenses/qurl-2.6.0-linux-{amd64,arm64}.spdx.json`.
Their module/version/license sets are identical. The exact license and
NOTICE files from the corresponding pinned module archives follow below.
These files preserve each dependency's copyright, conditions, disclaimers,
and any upstream NOTICE material without substituting a generic license.

`github.com/fatedier/yamux` is the MPL-2.0 component in the qURL binary.
Its exact pinned Source Code Form, including the license, is supplied in
`third_party_licenses/yamux-source/` in both the source distribution and
container image. Access Pages has not modified that source.

The final Python base image is Python 3.12.14. Its exact license is retained
at `/usr/local/lib/python3.12/LICENSE.txt` in the image and copied to
`third_party_licenses/Python-3.12.14-LICENSE` in this source distribution.
Debian base-image package license/copyright records remain under
`/usr/share/doc` in the final image. The locally served
`static/vendor/qrcodegen.js` retains its complete MIT notice in its header.

| Embedded module | Version | SPDX license(s) | Supplied license/notice files |
| --- | --- | --- | --- |
| `cloud.google.com/go/auth` | `v0.20.0` | `Apache-2.0` | `LICENSE` |
| `cloud.google.com/go/auth/oauth2adapt` | `v0.2.8` | `Apache-2.0` | `LICENSE` |
| `cloud.google.com/go/compute/metadata` | `v0.9.0` | `Apache-2.0` | `LICENSE` |
| `cloud.google.com/go/iam` | `v1.12.0` | `Apache-2.0` | `LICENSE` |
| `cloud.google.com/go/kms` | `v1.33.0` | `Apache-2.0` | `LICENSE` |
| `cloud.google.com/go/longrunning` | `v1.2.0` | `Apache-2.0` | `LICENSE` |
| `github.com/Azure/go-ntlmssp` | `v0.1.1` | `MIT` | `LICENSE` |
| `github.com/armon/go-socks5` | `v0.0.0-20160902184237-e75332964ef5` | `MIT` | `LICENSE` |
| `github.com/aws/aws-sdk-go-v2` | `v1.46.0` | `Apache-2.0 AND BSD-3-Clause AND LicenseRef-a6e830174d62dafad3a718384772ea1f4c0e27989f050932dc442a5e3ddad080 AND LicenseRef-f19d6aac3a063b4ea43196472248ff68e277b7c2a9e0a193799134677d496cda` | `LICENSE.txt`, `NOTICE.txt`, `internal/sync/singleflight/LICENSE` |
| `github.com/aws/aws-sdk-go-v2/config` | `v1.33.3` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/credentials` | `v1.20.3` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | `v1.19.2` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | `v1.5.2` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | `v2.8.2` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/internal/v4a` | `v1.5.2` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | `v1.13.19` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | `v1.14.2` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/service/kms` | `v1.59.0` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/service/signin` | `v1.9.0` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/service/sso` | `v1.37.0` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | `v1.42.0` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/aws-sdk-go-v2/service/sts` | `v1.49.0` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/aws/smithy-go` | `v1.28.1` | `Apache-2.0 AND BSD-3-Clause AND LicenseRef-d4290ed64c2edd0fce1d84e3f9dfb2881240fe534def76b8cd29ed6af683e287` | `LICENSE`, `NOTICE`, `internal/sync/singleflight/LICENSE`, `transport/http/protocol/internal/json/internal/stdlib/LICENSE` |
| `github.com/cespare/xxhash/v2` | `v2.3.0` | `MIT` | `LICENSE.txt` |
| `github.com/coreos/go-oidc/v3` | `v3.18.0` | `Apache-2.0 AND LicenseRef-dccd26c6fd9c296daf44d0bc56bb4efc566edd4880381b3331c9a63e6e471338` | `LICENSE`, `NOTICE` |
| `github.com/cpuguy83/go-md2man/v2` | `v2.0.6` | `MIT` | `LICENSE.md` |
| `github.com/fatedier/golib` | `v0.8.2` | `Apache-2.0` | `LICENSE` |
| `github.com/fatedier/yamux` | `v0.0.0-20250825093530-d0154be01cd6` | `MPL-2.0` | `LICENSE` |
| `github.com/felixge/httpsnoop` | `v1.0.4` | `MIT` | `LICENSE.txt` |
| `github.com/go-jose/go-jose/v4` | `v4.1.4` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE`, `json/LICENSE` |
| `github.com/go-logr/logr` | `v1.4.3` | `Apache-2.0` | `LICENSE` |
| `github.com/go-logr/stdr` | `v1.2.2` | `Apache-2.0` | `LICENSE` |
| `github.com/golang/snappy` | `v1.0.0` | `BSD-3-Clause` | `LICENSE` |
| `github.com/google/s2a-go` | `v0.1.9` | `Apache-2.0` | `LICENSE.md` |
| `github.com/googleapis/enterprise-certificate-proxy` | `v0.3.17` | `Apache-2.0` | `LICENSE` |
| `github.com/googleapis/gax-go/v2` | `v2.24.1` | `BSD-3-Clause` | `LICENSE` |
| `github.com/gorilla/mux` | `v1.8.1` | `BSD-3-Clause` | `LICENSE` |
| `github.com/klauspost/cpuid/v2` | `v2.3.0` | `MIT` | `LICENSE` |
| `github.com/klauspost/reedsolomon` | `v1.12.0` | `MIT` | `LICENSE` |
| `github.com/layervai/frp` | `v1.0.2-0.20260916024338-1a3b5509d23d` | `Apache-2.0` | `LICENSE` |
| `github.com/layervai/qurl-connector` | `v0.14.0` | `Apache-2.0` | `LICENSE` |
| `github.com/layervai/qurl-go` | `v0.17.0` | `MIT` | `LICENSE` |
| `github.com/layervai/qurl-integrations` | `v1.8.1-0.20260917025645-b77efb41a167` | `MIT` | `LICENSE` |
| `github.com/pelletier/go-toml/v2` | `v2.4.3` | `MIT` | `LICENSE` |
| `github.com/pires/go-proxyproto` | `v0.15.0` | `Apache-2.0` | `LICENSE` |
| `github.com/pkg/errors` | `v0.9.1` | `BSD-2-Clause` | `LICENSE` |
| `github.com/quic-go/quic-go` | `v0.60.0` | `MIT AND LicenseRef-2c8d4ff4244edf09d99dcd428d278e47a059d24f0030b38c1ab38e93b1c8030c` | `LICENSE`, `assets/LICENSE.md` |
| `github.com/russross/blackfriday/v2` | `v2.1.0` | `BSD-2-Clause` | `LICENSE.txt` |
| `github.com/samber/lo` | `v1.47.0` | `MIT` | `LICENSE` |
| `github.com/songgao/water` | `v0.0.0-20200317203138-2b4b6d7c09d8` | `BSD-3-Clause` | `LICENSE` |
| `github.com/spf13/cobra` | `v1.10.2` | `Apache-2.0` | `LICENSE.txt` |
| `github.com/spf13/pflag` | `v1.0.10` | `BSD-3-Clause` | `LICENSE` |
| `github.com/templexxx/cpu` | `v0.1.1` | `BSD-3-Clause` | `LICENSE` |
| `github.com/templexxx/xorsimd` | `v0.4.3` | `MIT` | `LICENSE` |
| `github.com/tjfoc/gmsm` | `v1.4.1` | `Apache-2.0` | `LICENSE` |
| `github.com/vishvananda/netlink` | `v1.3.0` | `Apache-2.0` | `LICENSE` |
| `github.com/vishvananda/netns` | `v0.0.4` | `Apache-2.0` | `LICENSE` |
| `github.com/xtaci/kcp-go/v5` | `v5.6.13` | `MIT` | `LICENSE` |
| `go.opentelemetry.io/auto/sdk` | `v1.2.1` | `Apache-2.0` | `LICENSE` |
| `go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc` | `v0.67.0` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE` |
| `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` | `v0.67.0` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE` |
| `go.opentelemetry.io/otel` | `v1.44.0` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE` |
| `go.opentelemetry.io/otel/metric` | `v1.44.0` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE` |
| `go.opentelemetry.io/otel/trace` | `v1.44.0` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE` |
| `go.yaml.in/yaml/v3` | `v3.0.4` | `Apache-2.0 AND MIT` | `LICENSE`, `NOTICE` |
| `golang.org/x/crypto` | `v0.56.0` | `BSD-3-Clause` | `LICENSE` |
| `golang.org/x/net` | `v0.58.0` | `BSD-3-Clause` | `LICENSE` |
| `golang.org/x/oauth2` | `v0.36.0` | `BSD-3-Clause` | `LICENSE` |
| `golang.org/x/sync` | `v0.22.0` | `BSD-3-Clause` | `LICENSE` |
| `golang.org/x/sys` | `v0.47.0` | `BSD-3-Clause` | `LICENSE` |
| `golang.org/x/term` | `v0.45.0` | `BSD-3-Clause` | `LICENSE` |
| `golang.org/x/text` | `v0.41.0` | `BSD-3-Clause` | `LICENSE` |
| `golang.org/x/time` | `v0.15.0` | `BSD-3-Clause` | `LICENSE` |
| `golang.zx2c4.com/wireguard` | `v0.0.0-20231211153847-12269c276173` | `MIT` | `LICENSE` |
| `google.golang.org/api` | `v0.288.0` | `BSD-3-Clause` | `LICENSE`, `internal/third_party/uritemplates/LICENSE` |
| `google.golang.org/genproto` | `v0.0.0-20260715232425-e75dac1f907d` | `Apache-2.0` | `LICENSE` |
| `google.golang.org/genproto/googleapis/api` | `v0.0.0-20260715232425-e75dac1f907d` | `Apache-2.0` | `LICENSE` |
| `google.golang.org/genproto/googleapis/rpc` | `v0.0.0-20260715232425-e75dac1f907d` | `Apache-2.0` | `LICENSE` |
| `google.golang.org/grpc` | `v1.83.2` | `Apache-2.0` | `LICENSE`, `NOTICE.txt` |
| `google.golang.org/protobuf` | `v1.36.12` | `BSD-3-Clause` | `LICENSE` |
| `gopkg.in/ini.v1` | `v1.67.0` | `Apache-2.0` | `LICENSE` |
| `gopkg.in/yaml.v2` | `v2.4.0` | `Apache-2.0 AND MIT` | `LICENSE`, `LICENSE.libyaml`, `NOTICE` |
| `gopkg.in/yaml.v3` | `v3.0.1` | `Apache-2.0 AND MIT` | `LICENSE`, `NOTICE` |
| `k8s.io/apimachinery` | `v0.28.8` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE`, `third_party/forked/golang/LICENSE` |
| `k8s.io/utils` | `v0.0.0-20230406110748-d93618cff8a2` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE`, `inotify/LICENSE`, `internal/third_party/forked/golang/LICENSE`, `third_party/forked/golang/LICENSE` |
| `sigs.k8s.io/json` | `v0.0.0-20221116044647-bc3834ca7abd` | `Apache-2.0 AND BSD-3-Clause` | `LICENSE` |
| `sigs.k8s.io/yaml` | `v1.3.0` | `BSD-3-Clause AND MIT` | `LICENSE` |
