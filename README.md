# chttp

chttp 是 Go [`net/http`](https://pkg.go.dev/net/http) 的分支，提供熟悉的 HTTP 客户端和服务端 API。客户端可以指定请求头顺序、HTTP/1.1 头名大小写、TLS ClientHello，以及 HTTP/2 的伪头顺序和建连帧。适用于需要控制报文格式、验证协议兼容性或比较客户端行为的 Go 项目。

[安装](#安装) · [快速开始](#快速开始) · [请求头](#请求头) · [TLS 和 JA3](#tls-和-ja3) · [HTTP/2](#http2) · [性能对比](#性能对比) · [调试与测试](#调试与测试) · [升级与迁移](#升级与迁移)

## 安装

当前源码要求 Go 1.27 或更高版本。在已有 Go 模块中添加依赖。[go.mod](go.mod)

```sh
go get github.com/wangluozhe/chttp
```

包名是 `http`。应用中可以显式使用 `chttp` 作为导入别名。

```go
import chttp "github.com/wangluozhe/chttp"
```

`go get` 解析已发布的模块版本。使用尚未发布的本地源码时，可以在应用模块中用 `replace` 指向 chttp 的检出目录。下面假设应用和 chttp 位于同一个父目录。在应用中加入 chttp 的导入后运行这些命令。

```sh
go mod edit -replace=github.com/wangluozhe/chttp=../chttp
go mod tidy
```

## 快速开始

下面的 `main.go` 启动本地 HTTP 服务并发送一次请求，可以用 `go run .` 运行。访问已有服务时，把 `server.URL` 换成实际地址。

```go
package main

import (
	"fmt"
	"io"
	"log"
	"time"

	chttp "github.com/wangluozhe/chttp"
	"github.com/wangluozhe/chttp/httptest"
)

func main() {
	server := httptest.NewServer(chttp.HandlerFunc(func(w chttp.ResponseWriter, r *chttp.Request) {
		fmt.Fprintln(w, "hello from chttp")
	}))
	defer server.Close()

	client := &chttp.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()

	resp, err := client.Get(server.URL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s %s\n%s", resp.Proto, resp.Status, body)
}
```

应用可以并发复用同一个 `Client` 和 `Transport`。首次发送前完成 transport 配置，每个请求按需设置 context 和请求头。正常读取响应体时，读到 EOF 后再关闭有助于复用连接。需要从默认配置派生自定义 transport 时，使用 `chttp.DefaultTransport.(*chttp.Transport).Clone()`。[client.go](client.go) · [transport.go](transport.go)

## 请求头

这些配置项是 `Request.Header` 中的本地序列化元数据。

| 配置 | 作用 |
| --- | --- |
| `chttp.HeaderOrderKey` | 指定 HTTP/1.1、HTTP/2 普通请求头的顺序。头名比较忽略大小写，未列出的头在可排序字段中按键名排列。 |
| `chttp.UnChangedHeaderKey` | 指定 HTTP/1.1 发送时所用的头名大小写。HTTP/2 按协议使用小写头名。 |
| `chttp.PHeaderOrderKey` | 指定 HTTP/2 伪头顺序，如 `:method`、`:authority`、`:scheme`、`:path`。缺少的必需伪头按默认顺序补齐。 |

对一个已创建的 `req`，下面的 HTTP/1.1 配置会把 `x-Request-ID` 排在 `Host` 和 `Accept` 前面。`Host` 等由请求写入器生成的可排序字段也可加入 `HeaderOrderKey`。

```go
req.Header.Set("X-Request-ID", "demo")
req.Header.Set("Accept", "text/plain")
req.Header[chttp.HeaderOrderKey] = []string{"x-request-id", "host", "accept"}
req.Header[chttp.UnChangedHeaderKey] = []string{"x-Request-ID"}
```

HTTP/1.1 的请求行和由传输层单独写入的 `Connection`、`Trailer` 有各自的位置。HTTP/2 先写伪头，再写普通头，`Cookie` 可以拆成多个字段。可在回归测试中检查实际发送的顺序。[request.go](request.go) · [header.go](header.go) · [internal/httpcommon/request.go](internal/httpcommon/request.go) · [transport_wire_test.go](transport_wire_test.go)

## TLS 和 JA3

默认握手使用 uTLS 的 `HelloGolang`。`Transport.TLSClientConfig` 接收 `*utls.Config`，可以用它设置 `RootCAs`、`ServerName` 或 TLS 版本限制。`net/http` 基准使用标准库自己的 `crypto/tls` 握手。[transport.go](transport.go) · [tlsextensions.go](tlsextensions.go)

| 配置 | 作用 |
| --- | --- |
| `Transport.JA3` | 接收五段逗号分隔的 JA3 字符串，依次描述版本、密码套件、扩展编号、支持组和 EC 点格式。各段内的多项用 `-` 分隔。TLS 版本协商还取决于 `SupportedVersions` 和对端。 |
| `Transport.TLSExtensions` | 指定签名算法、支持版本、Key Share、证书压缩等扩展内容。启用对应扩展后才会用到这些参数。 |
| `Transport.RandomJA3` | 在创建新 TLS 连接时打乱可重排的扩展。固定配置的回归测试可保留默认值 `false`。 |
| `Transport.UserAgent` | 参与 JA3 模式下的 ClientHello 配置选择。HTTP 请求头里的 `User-Agent` 通过 `req.Header.Set` 设置。 |
| `Transport.ClientHelloHexStream` | 接收一条 TLS ClientHello 记录的十六进制字符串。uTLS 根据解析结果构造新的握手，SNI 和临时密钥取自当前连接。 |

ClientHello 的来源依次为 `TLSExtensions.ClientHelloHexStream`、`Transport.ClientHelloHexStream`、`Transport.JA3` 和默认握手，使用第一个有效配置项。JA3 和重放路径的 ALPN 会遵从明确设置的 `Transport.Protocols` 或 `ForceHTTP1`。使用 JA3 配置协商 HTTP/2 时，JA3 需要包含 ALPN 扩展 `16`。[tlsextensions.go](tlsextensions.go)

HTTPS 握手由 `Transport` 管理时，这些配置在建连阶段生效。普通 TCP 拨号定制放在 `DialContext`。使用 `DialTLSContext` 接管直连 HTTPS 时，由回调负责 TLS 配置和握手。一个正在复用的连接沿用自身的握手结果。[transport.go](transport.go)

## HTTP/2

Go 标准库已提供 HTTP/2 协议协商、`Protocols`、`HTTP2Config` 和 Extended CONNECT。一般的协议选择及流控参数可通过 `Transport.Protocols` 和 `Transport.HTTP2` 设置。chttp 的 `HTTP2ConfigureTransports` 额外提供有序 SETTINGS、连接级 `WINDOW_UPDATE` 和优先级配置。[上游 HTTP2Config](https://github.com/golang/go/blob/568727209742/src/net/http/http.go) · [http2client.go](http2client.go)

`DefaultTransport` 对 HTTPS 默认尝试 HTTP/2。自建 `Transport` 时，可以用 `Protocols` 明确启用 HTTP/1.1 和 HTTP/2。仅启用 HTTP/1.1 可用 `ForceHTTP1`，仅启用 TLS 上的 HTTP/2 可将 `Protocols` 设为只有 `HTTP2`。要对 `http://` 使用明文 HTTP/2，启用 `UnencryptedHTTP2` 并关闭 `HTTP1`，对端须支持直接建立 HTTP/2 连接。[http.go](http.go) · [transport.go](transport.go)

### 本地验证 JA3 和 HTTP/2

下面的 `http2_test.go` 启动本地 TLS 服务，使用测试服务提供的证书信任配置。测试通过 `resp.Proto` 和 ALPN 验证协商，并读取响应体。可用 `go test -run '^TestCustomHTTP2$'` 运行。

```go
package chhttpdemo

import (
	"io"
	"testing"

	utls "github.com/refraction-networking/utls"
	chttp "github.com/wangluozhe/chttp"
	"github.com/wangluozhe/chttp/httptest"
)

func TestCustomHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(chttp.HandlerFunc(func(w chttp.ResponseWriter, r *chttp.Request) {
		io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	transport := client.Transport.(*chttp.Transport)
	transport.Protocols = new(chttp.Protocols)
	transport.Protocols.SetHTTP2(true)
	transport.JA3 = "771,4865-4866-4867,0-10-11-13-16-43-45-51,29-23-24,0"
	transport.TLSExtensions = &chttp.TLSExtensions{
		NotUsedGREASE: true,
		SupportedVersions: &utls.SupportedVersionsExtension{
			Versions: []uint16{utls.VersionTLS13},
		},
	}

	h2, err := chttp.HTTP2ConfigureTransports(transport)
	if err != nil {
		t.Fatal(err)
	}
	h2.HTTP2Settings = &chttp.HTTP2Settings{
		Settings: []chttp.HTTP2Setting{
			{ID: chttp.HTTP2SettingEnablePush, Val: 0},
			{ID: chttp.HTTP2SettingInitialWindowSize, Val: 1 << 20},
		},
		ConnectionFlow: 1 << 20,
	}

	req, err := chttp.NewRequestWithContext(t.Context(), chttp.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "chttp-demo/1.0")
	req.Header[chttp.HeaderOrderKey] = []string{"user-agent", "accept"}
	req.Header[chttp.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("expected HTTP/2 over TLS, got %s", resp.Proto)
	}
	if resp.StatusCode != chttp.StatusOK {
		t.Fatalf("unexpected status: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("unexpected body: %q", body)
	}
}
```

若已将快速开始的 `main.go` 放在同一个目录，用 `package main` 作为测试文件的包声明。

`Settings` 非空时会按切片顺序替换默认的初始 SETTINGS。`ConnectionFlow` 是初始连接级 `WINDOW_UPDATE` 的增量。`PriorityFrames` 可指定单独的 PRIORITY 帧，`HeaderPriority` 可指定 HEADERS 中的优先级，`HeadersID` 可指定起始请求流 ID，显式值须为奇数，且会考虑已发送的优先级帧。`SettingsAck` 用于测试初始化时额外发送 ACK 的行为。[internal/http2/transport.go](internal/http2/transport.go) · [更多 SETTINGS 示例](examples/http2settings-test.go)

## 性能对比

基准在同一台 Windows/amd64 机器上运行，CPU 为 Intel Core Ultra 7 155H，工具链为 `devel go1.28-568727209742`，`GOMAXPROCS=2`。各客户端按顺序对本地同一种标准库 HTTP/2 服务发送 GET，每次检查实际响应协议并读完响应体。每组测 5 次，耗时、`B/op` 和 `allocs/op` 各取中位数。

复用组在计时前预热，只建立一次连接。新建组每个请求重新建立 TCP 和 TLS 连接。chttp 的自定义组启用固定 JA3、HTTP/2 SETTINGS 和伪头顺序。标准 `net/http` 使用原生 ClientHello 和 HTTP/2 默认配置。[chttp 基准](transport_bench_test.go) · [net/http 基准](benchmarks/nethttp/transport_bench_test.go)

| 客户端 | 配置 | 复用连接<br>耗时 / B/op / allocs/op | 每次新建连接<br>耗时 / B/op / allocs/op |
| --- | --- | ---: | ---: |
| 标准 `net/http` | 原生 | 131.6 µs / 4,522 / 41 | 3.665 ms / 85,394 / 565 |
| 旧版 chttp（`29407c9`） | 默认 | 153.8 µs / 4,304 / 42 | 3.409 ms / 105,086 / 646 |
| 当前 chttp | 默认 | 140.1 µs / 4,538 / 41 | 3.169 ms / 101,852 / 613 |
| 旧版 chttp（`29407c9`） | 自定义 JA3 和 HTTP/2 | 170.0 µs / 5,467 / 52 | 3.756 ms / 140,107 / 1,075 |
| 当前 chttp | 自定义 JA3 和 HTTP/2 | 147.3 µs / 5,369 / 45 | 3.780 ms / 131,748 / 985 |

启用自定义配置时，当前 chttp 复用连接的耗时比旧版低 **13.4%**，比标准库原生配置高约 **12%**。每次新建连接的分配次数从 **1,075** 降到 **985**，耗时中位数基本持平。新建连接的耗时波动较大，这组结果适用于本机顺序请求。当前 chttp 默认配置下复用连接的分配次数与标准库相同，耗时高约 **6.5%**。

### 复现基准

在仓库根目录依次运行。复现表格时使用同一 Go 工具链，并设置 `GOMAXPROCS=2`。基准会在计时前用 `PATH` 中的 `go` 构建本地服务端。

```sh
go test -mod=vendor -run '^$' -bench '^BenchmarkTransportHTTP2' -benchmem -benchtime=700ms -count=5 -cpu=2 .
go test -mod=vendor -run '^$' -bench '^BenchmarkTransportHTTP2' -benchmem -benchtime=700ms -count=5 -cpu=2 ./benchmarks/nethttp
```

复测旧版时，用 `git worktree add --detach ../chttp-before 29407c9` 创建历史工作树，将当前的 `transport_bench_test.go` 和 `internal/transportbenchserver/` 复制到其中的同名路径，再从旧版目录运行第一条基准命令。HTTP/1.1 和 TLS + HTTP/1.1 的基准也在同一套测试中，可将过滤条件改为 `'^BenchmarkTransport(TLS)?HTTP1'`。

## 调试与测试

- 请求跟踪使用 `github.com/wangluozhe/chttp/httptrace`，可观察拨号、TLS 握手及连接复用。代理可设置 `Transport.Proxy`，用 `chttp.ProxyURL` 指定固定地址，或用 `chttp.ProxyFromEnvironment` 读取 `http_proxy`、`https_proxy`、`no_proxy` 及其大写形式。[跟踪示例](examples/httptrace-test.go) · [代理示例](examples/proxy-test.go)
- `github.com/wangluozhe/chttp/httputil` 提供请求和响应转储。将请求的 `ProtoMajor` 设为 `2` 可查看 HTTP/2 风格的文本转储。实际协议由 transport 与服务端协商，帧顺序可用抓包测试核对。[转储示例](examples/dump-test.go)
- [examples/](examples/) 内是独立程序，可以用 `go run -mod=vendor ./examples/http2-test.go` 这样的命令逐文件运行。部分示例依赖外部服务或本地代理。[TLS 扩展示例](examples/tlsextensions-test.go) · [ClientHello 重放示例](examples/ClientHelloHexStream-test.go)

在仓库根目录运行全量测试和本地抓包测试。抓包测试覆盖请求头顺序、TLS 与 ALPN、JA3 和 ClientHello 重放，以及 HTTP/2 建连帧和请求体。

```sh
go test -mod=vendor ./...
go test -mod=vendor -run '^TestTransportWire$' -count=1 -v .
```

## 升级与迁移

当前网络层以 Go `master` 的 `568727209742` 为基线。HTTP/1.1 和 HTTP/2 共用上游连接池，由同一个 `Transport` 处理连接复用、并发拨号和每主机连接上限。HTTP/2 头部排序结果在大小校验和 HPACK 编码之间复用，定制握手使用 uTLS `ApplyPreset` 自带的复制。[上游快照](https://github.com/golang/go/tree/568727209742/src/net/http) · [transport_pool.go](transport_pool.go) · [internal/httpcommon/request.go](internal/httpcommon/request.go)

从 `net/http` 迁移时，把一起使用的 `Client`、`Request`、`Response`、`Handler` 及 `httptest`、`httputil`、`httptrace` 等配套包切换到 chttp 的导入路径。两套库分别定义这些类型，接入现有中间件时应核对函数签名。自定义 TLS 配置使用 `github.com/refraction-networking/utls` 的类型。

从旧版 chttp 升级时，`HTTP2ConfigureTransports` 和基于 `HTTP2Settings` 的配置方式继续可用。JA3 和 ClientHello 重放现在都遵从显式 ALPN 协议限制。涉及旧接口的调用可按下表调整。

| 旧用法 | 当前用法 |
| --- | --- |
| 直接调用 `HTTP2Transport.RoundTrip` 或 `RoundTripOpt` | 使用 `Client.Do` 或父 `Transport.RoundTrip`。需要专用连接时使用 `Transport.NewClientConn`。 |
| 在 `HTTP2Transport` 设置 `TLSClientConfig`、`DialTLS` 或 `DialTLSContext` | 在父 `Transport` 配置 TLS 或拨号，按父 transport 的回调签名调整。 |
| 设置 `HTTP2Transport.ConnPool` | 由父 `Transport` 的连接池管理 HTTP/1.1 与 HTTP/2 连接，通过 `MaxConnsPerHost` 等字段控制连接数。 |
| 调用 `Transport.CancelRequest` | 使用 `NewRequestWithContext` 或 `Request.WithContext` 传递可取消的 context。旧方法随上游成为空操作。 |

HTTP/3 的旧注册钩子保留给外部实现。内置客户端和服务端的文档及基准覆盖 HTTP/1.1 与 HTTP/2。[http3.go](http3.go) · [transport.go](transport.go)

## 上游来源

`net/http` 派生文件保留 Go Authors 的版权声明，并指向 Go 项目的 BSD-style 许可证。当前仓库根目录缺少项目许可证文件。[Go LICENSE](https://github.com/golang/go/blob/568727209742/LICENSE)
