# cronet-go 支持 naiveproxy preamble —— 方案设计

> 状态：**方案已实施完成（v7），测试全绿**。所有待决策项已在 §11 拍板；实施记录与实测证据见 §12。
> 本文所有结论均来自 `naiveproxy/` 子模块（Chromium 154.0.8037.49）源码阅读 + 对 `lib/windows_amd64/libcronet.dll` 的实机验证。
> 目标：让 libcronet 的对外行为尽量贴近原生 naive 客户端（klzgrad/naiveproxy 的 `naive` 二进制）。
> v2：补充内容编码（br/zstd）方案与评审意见的结论（见 §5 与 §11）。
> v3：补充第二轮实证（E10–E13）：QUIC 下的隔离轮换、CONNECT 的空 `user-agent`、会话空闲寿命（h2 ≥10min / QUIC ~30s）及由此产生的 §6.7 修正。
> v4：用用户自编的 klzgrad Caddy + 预编译 libcronet 做了**真实部署端到端验证**（E14 h2 / E15 h3，§4.1），并补上两个部署前提（`probe_resistance`、ACL）。
> v5：两个指纹敏感的纯函数（HTML 抽取、sec-ch-ua 生成）已把 Go 版与**原 C++ 原函数**逐字节比对通过（E16/E17）。
> v6（定稿）：写入评审最终决策 —— `PreambleTimeout=10s`、`TunnelTimeout` 按 GOOS、解码器默认编入、一并修 CONNECT 空 `user-agent`、idle grace 保持（§11 表格）。
> v7（已实施）：按本方案完成实现，单元测试 + 集成测试（含对真实 klzgrad Caddy 的端到端）全部通过；实施中修正的三处细节与完整验证证据见 §12。

---

## 1. 背景：preamble 是什么

naiveproxy 从 v147.0.7727.49-3 起引入了 preamble（release note 原文）：

> Now NaiveProxy will send realistic Chrome requests as preambles before and during tunneled TLS handshakes, making traffic analysis based on the initial period of TLS connections much harder.
> The preamble URLs are extracted from the root page source of the fronting web server, and can be configured by editing the root page.

也就是说：客户端在建立隧道（CONNECT）之前/期间，先像 Chrome 一样访问 naive 服务器所在的站点（`https://<server>/` 及页面里的 css/js/img），使一条连接的开头看起来像一次正常的网页加载，而不是"握手成功后立刻 CONNECT"。

对 cronet-go 而言：目前 `DialEarly()` 直接在 `https://<server>` 上开一条 `CONNECT` 流（`naive_client.go:490`），完全没有 preamble 流量，这是与原生 naive 客户端最明显的指纹差异。

---

## 2. 原生 naive 客户端的 preamble 实现（源码梳理）

### 2.1 参与文件

| 文件 | 作用 |
|---|---|
| `naiveproxy/src/net/tools/naive/preamble_getter.{h,cc}` | preamble 请求的构造、发送、响应解析、子资源发现 |
| `naiveproxy/src/net/tools/naive/naive_proxy.cc` | 触发时机、tunnel（=并发槽）状态机、连接清理 |
| `naiveproxy/src/net/tools/naive/naive_proxy_delegate.{h,cc}` | 提供 preamble 请求头、记录 preamble 响应头 |
| `naiveproxy/src/net/spdy/spdy_proxy_client_socket.cc` | 真正把 preamble 请求变成 h2 帧（含优先级、鉴权头处理） |
| `naiveproxy/src/net/quic/quic_proxy_client_socket.cc` | 同上，h3 版本 |
| `naiveproxy/src/net/tools/naive/naive_config.h` | `tunnel_timeout` / `idle_timeout` 默认值 |

### 2.2 触发流程

`NaiveProxy::DoAcceptComplete()`（`naive_proxy.cc:144`）：

```
Tunnel& tunnel = tunnels_[next_id_ % concurrency_];   // 每个并发槽一份状态
if (IsSessionCapable()) {                            // 仅 https/quic proxy 才做（HTTP/1 不行）
  if (tunnel.deadline.is_null()) {                    // 该槽还没有会话
    tunnel.deadline = now + tunnel_timeout;
    -> State::kPreamble                              // 完整 preamble，且阻塞本次 accept
  } else if (now > tunnel.deadline) {                 // 会话到期：轮换
    tunnel.nak = NetworkAnonymizationKey::CreateTransient();  // 换 NAK => 换连接
    tunnel.deadline = now + tunnel_timeout;
    tunnel.url_getter.reset();                        // 重新发现子资源
    -> State::kPreamble                              // 完整 preamble，阻塞本次 accept
  } else {
    tunnel.url_getter->StartOne();                    // 随机挑一个已发现请求，后台发
    -> State::kConnect                               // 不阻塞
  }
} else -> State::kConnect
```

要点：

1. **第一个落到该并发槽的连接会等完整 preamble 跑完才发 CONNECT**（`DoPreamble` → `DoPreambleComplete` → `DoConnect`，`naive_proxy.cc:182/191/200`）。
2. **preamble 失败不阻断 CONNECT**：`DoPreambleComplete()` 只打 `LOG(WARNING)` 然后继续 `kConnect`（对应上游 commit "Don't get stuck on preamble error"）。
3. **preamble 请求走普通 HTTP 语义**（`GET`/`HEAD`），而不是隧道请求。源码注释解释得很清楚：
   > The preamble requests have to be sent through this API instead of regular URLRequests because regular URLRequests are tunneled first in CONNECT requests. The purpose of preamble is to send regular GET requests.

   （注意：这是 naive 自己有 proxy chain 的缘故。cronet-go 直连 naive 服务器，没有 proxy，不存在"先被隧道"的问题。）
4. `StartOne()` 在"会话还活着"的每一条连接上都会触发一次（`preamble_getter.cc:508`），即隧道使用期间持续产生背景流量。
5. `CleanUpIdleConnections()`（`naive_proxy.cc:351`）每分钟跑一次：关闭 idle > `idle_timeout` 或存活超过 `tunnel_timeout` 的隧道，并 `session_->CloseIdleConnections("Rotate old tunnels")`。
6. 默认超时（`naive_config.h:49-57`）：桌面/Android 分别为 `tunnel_timeout=1800/600`、`idle_timeout=600/300`（秒）。

### 2.3 PreambleGetter 内部

构造（`preamble_getter.cc:79`）：

- `requests_[0] = {path:"/", ext:""}`，**永远保留**，即使根请求失败；
- `root_ = GURL("https://" + proxy_server->host_port_pair().ToString()).GetAsReferrer()`，即 `https://<server>/`（GURL 会省略默认端口）；
- `user_agent_` / `sec_ch_ua*` 来自 `embedder_support::GetUserAgent()` 与 `GetUserAgentMetadata()`（**进程启动时生成，同一进程内固定**）。

`Start(callback, index, log_url)`（`preamble_getter.cc:213`）：

- 组装请求头（见 2.4），交给 `NaiveProxyDelegate::SetPreambleRequestHeaders()`；
- 用一个特殊 endpoint 走 `InitSocketHandleForHttpRequest()`：`SchemeHostPort("http", "preamble", index)`，即用 "preamble" 这个假主机名 + 槽位号作为端口，保证这些请求进入 proxy socket 池但不会污染真实站点的缓存键；
- 请求优先级：`path=="/"` 或 `ext=="css"` → `HIGHEST`，否则 `LOWEST`（源码里 `ext == ".js"` 分支是死代码，`ext` 不带点）。

读取与子资源发现（`DoRead` / `DoReadComplete`，`preamble_getter.cc:299/442`）：

- 64 KiB 一读，读到 EOF/错误为止（root 请求是阻塞的；子请求 fire-and-forget）；
- root 请求的响应体会先按 `content-encoding` 解压（`FilterSourceStream::GetContentEncodingTypes`，支持 gzip/deflate/br/zstd），再用一个手写 HTML 扫描器 `ExtractLinkAndScriptURLs()` 抽取 `<link href>` / `<script src>` / `<img src>`；
- 只接受同 host + 同端口、且扩展名属于 `{css, js, png, gif, jpg, jpeg, webp, bmp, avif, jxl}` 的资源，按 path 去重，发现一个就立刻异步发起对应的请求（`HEAD`，css/js 用 `GET`）；
- 每读完一块，只保留最后一块内容再解析（`req.last_content = new_data`），跨块的标签可能漏掉——这是原实现的行为；
- 只有 index 0 的响应会解析（子资源的响应体直接丢弃）。

### 2.4 请求头（逐字复制，`preamble_getter.cc:141` / `:166`）

根请求 `GET /`：

```
sec-ch-ua: <品牌列表>
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
upgrade-insecure-requests: 1
user-agent: <Chrome UA>
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
sec-fetch-site: none
sec-fetch-mode: navigate
sec-fetch-user: ?1
sec-fetch-dest: document
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
priority: u=0, i
```

子请求（`ext` 决定）：

| 头 | css | js | 图片 |
|---|---|---|---|
| method | GET | GET | HEAD |
| accept | `text/css,*/*;q=0.1` | `*/*` | `image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8` |
| sec-fetch-dest | style | script | image |
| priority | `u=0` | `u=2` | `i` |
| 其它 | `sec-ch-ua-platform` / `user-agent` / `sec-ch-ua` / `sec-ch-ua-mobile` / `sec-fetch-site: same-origin` / `sec-fetch-mode: no-cors` / `referer: https://<server>/` / `accept-encoding` / `accept-language` 同上 | | |

**preamble 请求明确不带**（`spdy_proxy_client_socket.cc:430-500`，因为 `preamble_index_` 有值时走的是 `OnBeforePreambleRequest` 分支，直接 `return`，不会走 `OnBeforeTunnelRequest`，并且 `authorization_headers_.Clear()`）：

- `padding`
- `padding-type-request`
- `proxy-authorization`
- 用户自定义 `extra_headers`
- `fastopen`

（为什么必须不带鉴权头，在 §4.1 用真实 Caddy 验证了：非 CONNECT 请求只有未认证时才会被 forwardproxy 当作“正常访问网站”放行。）

流优先级（`spdy_proxy_client_socket.cc:487-492`，会覆盖 2.3 里传入的优先级）：

```
path == "/" 或 path 以 ".css" 结尾 → HIGHEST(=5)
path 以 ".js" 结尾                 → LOW(=3)
其它                               → LOWEST(=2)（即上面传入的默认值）
```

请求以 `NO_MORE_DATA_TO_SEND` 发出（`spdy_proxy_client_socket.cc:520`），即 `endOfStream = true`；响应状态码被完全忽略（`:592`，400/407 都无所谓，也不会触发 proxy auth 重试）。

### 2.5 UA / Client Hints 的确切取值

`src/build.sh:18` 显示 release 构建带 `is_chrome_branded=true`，因此：

- **UA**（`components/version_info/version_info_with_user_agent.cc:13` + `user_agent_utils.cc:954`）：
  ```
  Mozilla/5.0 (<unified platform>) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<major>.0.0.0 Safari/537.36
  ```
  例（Windows）：`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36`
  平台串按 OS 固定：Windows `Windows NT 10.0; Win64; x64`、macOS `Macintosh; Intel Mac OS X 10_15_7`、Linux `X11; Linux x86_64`、Android `Linux; Android 10; K`。
- **sec-ch-ua**：品牌列表 = `[grease, Chromium, "Google Chrome"]`（chrome branding 才带第三个），用 `major` 作种子做稳定洗牌，grease 品牌 = `Not<chars[m%11]>A<chars[(m+1)%11]>Brand`，版本 = `["8","99","24"][m%3]`。
  对 m=154：`chars[0]=" "`、`chars[1]="("`、版本 `99`、size-3 洗牌序 `orders[154%6=4]={2,0,1}` →
  ```
  sec-ch-ua: "Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"
  ```
- **sec-ch-ua-mobile** `?0`；**sec-ch-ua-platform**：Windows `"Windows"`、macOS `"macOS"`、Linux/Android `"Linux"`、ChromeOS `"Chromium OS"`。

这套值只依赖 Chromium 主版本号，Go 侧可以用十几行完全复刻，升级 Chromium 时自动跟随。

生成算法已按 E17 的方式与原 C++ 交叉比对过（major 100..199 输出完全一致），几个参考值：

| major | sec-ch-ua |
|---|---|
| 150 | `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"` |
| 153 | `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"` |
| 154 | `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"` |
| 155 | `"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"` |

---

## 3. cronet-go 现状

- 客户端是**直连** naive 服务器（不走任何 HTTP proxy），隧道用 `StreamEngine` 的双向流实现：
  `naive_client.go:490` → `conn.Start("CONNECT", c.serverURL, headers, 0, false)`。
- `c.streamEngines[i]` 与 `c.engines[i]` 一一对应（`naive_client.go:355`），并发槽语义与 naive 的 `tunnels_[i]` 天然对应；并发选择也是 round-robin（`naive_client.go:485-491`），与 `next_id_ % concurrency_` 一致。
- 双向流底层走 `net::BidirectionalStream` → `HttpStreamFactory::RequestBidirectionalStreamImpl()`，`enable_ip_based_pooling_for_h2=true`，**与普通 URLRequest 共用同一个 session pool**（`naiveproxy/src/net/http/bidirectional_stream.cc:227`）。
- 内部头支持（`naiveproxy/src/net/http/bidirectional_stream.cc:210-223`）：
  - `-network-isolation-key: <URL>` → 转成 `NetworkIsolationKey`（SchemefulSite），从而隔离 socket pool / session pool；
  - `-force-quic: true` → `HttpRequestInfo::force_quic`。
- `Engine.Version()` 可运行时拿到 Chromium 版本（实测 `154.0.8037.49`）；`EngineParams.SetUserAgent()` 可设置引擎级 UA。
- `URLRequestParams`（`url_request_params_cgo.go`）**没有**任何设置 NAK / 强制 QUIC 的接口（`QuicHint` 只提供 alt-svc 备用端口，与本场景无关）。

---

## 4. 已完成的实机验证（libcronet 154.0.8037.49 + sing-box 1.13.21）

> 环境：Windows，`CGO_ENABLED=0 -tags with_purego`，DLL 取自 `lib/windows_amd64/libcronet.dll`。
> 为了不占用用户已在使用的 **10443**（用户自己的 sing-box naive inbound 端口，也正是 `test/main_test.go` 里写死的 `naiveServerPort`），实验另起了一个 sing-box naive inbound 监听 **127.0.0.1:10444**，自签证书 `example.org`。

| 编号 | 实验 | 结果 |
|---|---|---|
| E1 | 用 `StreamEngine` 发一条 `GET https://example.org:10444/`（带 2.4 的根请求头，`endOfStream=true`） | 服务端返回 `:status 400`、`content-length: 0`、空 body；连接**未**被断开，随后 `CONNECT` 隧道正常工作（echo 成功） |
| E2 | NetLog 抓包：先发 preamble GET，再发 CONNECT，再发一条 GET | 三条流共用 **1 条 TCP 连接（socket 19）+ 1 个 h2 session（source 21）**，stream_id = 1 / 3 / 5 |
| E3 | NetLog 抓包：给 preamble 流加 `-network-isolation-key: https://pool-1:443` | `TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET.group_id` 变为 `https://example.org:10444 <https://pool-1 same_site>`，**新建 socket 33 + h2 session 35**；相同 key 的第二条流复用同一 session（stream 1 / 3） |
| E4 | `QUIC=1` 时，preamble 流**不带** `-force-quic` | preamble 走 h2/TCP（`HTTP2_SESSION` src 21），CONNECT 走 QUIC（`QUIC_SESSION` src 28）——**两者分裂** |
| E5 | `QUIC=1` 且 preamble 流带 `-force-quic: true` | preamble 与 CONNECT 全部落在**同一个 QUIC session**（src 21），完全不建立 TCP 连接 |
| E6 | `Engine.Version()` | `154.0.8037.49`（可用于生成 UA / sec-ch-ua） |
| E7 | 扫 DLL 字符串表 | 不含 `Mozilla` / `AppleWebKit` / `Safari` 等 UA 模板串 → UA 必须由 Go 侧生成 |
| E8 | 本地 HTTPS 站点模拟 Caddy（按 `Accept-encoding` 选 zstd/br/gzip），分别用 **URLRequest** 和 **StreamEngine** 取首页 | URLRequest：服务端回 `content-encoding: zstd`，Go 收到的 body 已是**解压后的 182 字节 HTML**；NetLog 显示线上头**恰好只有我们设置的 12 个**，没有被追加任何头。Stream：拿到的是**原始 142 字节**（zstd magic `28 b5 2f fd`） |
| E9 | 对 Stream 收到的原始字节用 Go 解码（`andybalholm/brotli` + `klauspost/compress/zstd` + stdlib gzip/deflate） | zstd / br / gzip / deflate / identity **五种情况全部还原出 182 字节 HTML**，均能命中 `href="/static/site.css"` |
| E10 | QUIC 模式下同时使用 `-force-quic` + `-network-isolation-key`（两轮 epoch） | epoch0：preamble GET、CONNECT、再来一条 GET **共用同一个 `QUIC_SESSION`（src 15）**；epoch1（换 key）**新建 `QUIC_SESSION`（src 31）**且其内两条流共用。全程 **没有** `TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET` → QUIC 下的轮换与共享都成立 |
| E11 | 用原始 engine 发 CONNECT 流，对比是否 `params.SetUserAgent()` | 不设：线上出现 `user-agent: `（**空值**，任何浏览器都不会这样发）；设成 Chrome UA：`user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) … Chrome/154.0.0.0 Safari/537.36`，与原生 naive 的隧道请求一致（`proxy_client_socket.cc:43` 会给 CONNECT 加 user-agent）。同时确认 `-network-isolation-key` / `-connect-authority` **不会**泄漏到线上（分别被 `bidirectional_stream.cc:211` 和 `spdy_http_utils.cc:216` 消费掉） |
| E12 | h2：发一次 GET，空闲 600s 后再发一次，看 NetLog | 第二条请求**复用同一个 `HTTP2_SESSION`**（src 15，stream_id 1 → 3），全程无 `SSL_CONNECT`/`SOCKET_CLOSED` → **h2 会话空闲 10 分钟仍然存活**（与 `client_socket_pool.cc:42` 的 `used_idle_socket_timeout=300s` 不冲突：那个清理只在有新连接需求时才跑） |
| E13 | 同上，QUIC 模式 | 第一条请求后 `t+29.0s` 出现 `QUIC_SESSION_CLOSED {"details": "No recent network activity after 29010393us. Timeout:29s", "quic_error": 25}`（双方 transport params 都是 `max_idle_timeout 30000`）；`t+600s` 的第二次请求**新建了 `QUIC_SESSION`（src 27）** → **QUIC 会话空闲 30 秒就没了** |
| E14 | **真实部署端到端**：用用户自编的 `caddy.exe`（klzgrad/forwardproxy，`v2.11.6 + forwardproxy@d62c80d`）在前，`file_server` 提供带 css/js/img 的真实站点 + `encode`，监听 127.0.0.1:8443；客户端 = 用户自己的 `libcronet.dll` + `NaiveClient` | 见 §4.1，全部通过 |
| E15 | 同上，但 Caddy 开 `protocols h1 h2 h3`，客户端 `QUIC: true`，preamble 带 `-force-quic` | **全程 0 个 TCP socket pool**，preamble GET 与 CONNECT **共用唯一的 `QUIC_SESSION`（src 16）**，隧道数据回环成功（`hello-over-h3-caddy`）→ D5 在真实部署的 h3 上成立 |
| E16 | 把 `ExtractLinkAndScriptURLs` 逐行移植到 Go，并把**原生 C++ 函数原样抄成一个独立程序**（g++ 编译）跑同一批 14 个用例 + **真实 Caddy 解码后的 3040 字节首页** | 两边输出**逐字节一致**（含 `<img src="">` → `[""]` 这种容易看错的情况）；真实页面抽出 `/style.css` `/app.js` `/img/logo.png`，正确忽略 `/about.html` 与注释里的伪链接 |
| E17 | 同样方式交叉验证 **sec-ch-ua 品牌列表生成**（`GetGreasedUserAgentBrandVersion` + `GetProcessedGreasedBrandVersion` + `GetRandomOrder` + `ShuffleBrandList` + chrome branding 的 3 项列表） | Go 版与原 C++ 在 **major 100..199 全部一致**；154 的结果是 `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`（与 §2.5 手推结果一致） |

补充（源码交叉验证，非本地实验）：sing-box naive inbound 对非 CONNECT 请求返回 400 并丢弃（`protocol/naive/inbound.go`），klzgrad 的 naive server 行为类似 —— 即**裸 naive 服务器的根页面没有 HTML**，只有当 naive 服务器被前置在一个真实网站（Caddy/nginx + `probe_resistance`）后面时，preamble 才会发现子资源。release note 里说的 "can be configured by editing the root page" 就是指这个前置站点。

E1 的响应同时说明一个实现要点：**preamble 响应体没有 padding**，所以读 body 时不能包 `NewNaiveConn()`（那会按 padding 帧格式解析）。

### 4.1 真实部署端到端验证（E14，klzgrad Caddy forwardproxy）

用户自己编译的 `caddy.exe`（`v2.11.6` + `github.com/klzgrad/forwardproxy@v0.0.0-20250118002110-d62c80d3dd2c`，`caddy build-info` 确认）监听 **127.0.0.1:8443**，Caddyfile 按 naiveproxy README 的经典形态：

```
{ order forward_proxy before file_server; auto_https off; servers { protocols h1 h2 } }
127.0.0.1:8443 {
    bind 127.0.0.1
    tls <self-signed>
    encode
    forward_proxy { basic_auth test test; hide_ip; hide_via; probe_resistance }
    file_server { root <真实站点> }
}
```

站点是自己写的 `index.html`（3 KB，内含 `<link href=/style.css>` / `<script src=/app.js>` / `<img src=/img/logo.png>`）。客户端用**用户预编译的 libcronet.dll**，按本方案的顺序手动跑了一遍：preamble 根请求 → 子资源 → CONNECT → 换 isolation key。

实测结果（NetLog + Caddy access log 双向印证）：

```
HTTP2_SESSION src 16                     ← 全程只有 1 条 TLS 连接（epoch 0）
   stream 1  GET  /              200 zstd  ua=Chrome/154…  padding=no  auth=no
   stream 3  GET  /style.css     200       ua=Chrome/154…  padding=no  auth=no
   stream 5  GET  /app.js        200       ua=Chrome/154…  padding=no  auth=no
   stream 7  HEAD /img/logo.png  200       ua=Chrome/154…  padding=no  auth=no
   stream 9  CONNECT  :authority=127.0.0.1:50855(目标)  padding=yes  auth=yes  ua=<空！>
HTTP2_SESSION src 37                     ← 换成 https://naive-0-1:443 后新建的连接（NAK 轮换语义成立）
   stream 1  GET  /
```

隧道数据也真的通了（`NaiveClient.DialContext` → echo 服务器，`hello-through-real-caddy` 原样回来），说明 cronet-go 现有的 padding 帧实现与 klzgrad forwardproxy 的 padding 层互通。

同一套 Caddyfile 把 `protocols` 改成 `h1 h2 h3`、客户端改 `QUIC: true` 并给 preamble 加上 `-force-quic` 后（E15）：**全程 0 个 TCP socket pool**，preamble GET（h3 stream 0）与 CONNECT（h3 stream 4）共用同一个 `QUIC_SESSION`，隧道数据同样回环成功——即 D5 在真实部署的 h3 下也成立。

Caddy 侧 access log 同样记录：preamble 的 4 个请求 `Padding`/`Proxy-Authorization` 均为空、UA 是完整 Chrome UA；CONNECT 则相反（`Padding` + `Proxy-Authorization` 存在，UA 为空）。

**两条重要的部署结论（之前没意识到）**：

1. **preamble 请求必须不带 `Proxy-Authorization`，而且服务器侧必须开 `probe_resistance`。** klzgrad fork 里，非 CONNECT 请求只有在 `h.Hosts.Match(r)` 为真时才会 pass 给 `file_server`（`forwardproxy.go:261`），而 Caddyfile 不写 `hosts` 时 `MatchHost` 是空列表 → `MatchWithError` 对空列表返回 **false**（`caddy/v2/modules/caddyhttp/matchers.go:307`）。真正能走通的是**未认证时的 `probe_resistance` 分支**：`authErr != nil && ProbeResistance != nil` → `next.ServeHTTP`（`forwardproxy.go:269-274`）。这也解释了为什么原生 naive 在 preamble 分支里要 `authorization_headers_.Clear()`（`spdy_proxy_client_socket.cc:476`）——**带上了鉴权头就会被当成代理请求，而不是去看网站**。实测：不带 `probe_resistance` 时 preamble GET 得到 `407`，带上就是 `200 + text/html`。
2. **forwardproxy 默认 ACL 会拒绝回环/内网地址**（`forwardproxy.go:156-169` 默认 deny `127.0.0.0/8`、`10/8`、`192.168/16`、`::1/128` 等），而 CONNECT 是 Fast Open（先回 200 再去连目标），所以“先 200 再 RST”会让人误以为隧道代码有问题。验证时才需要 `acl { allow 127.0.0.1/32 }`。

---

## 5. 内容编码与前置真实站点（`br` / `zstd` 问题）

### 5.1 问题

用户典型部署是 `caddy { forwardproxy → naive 后端; encode; file_server }`：preamble 的 `GET /` 由 **Caddy 自己**（而不是 naive 后端）应答，返回一个真实网页。这带来两个问题：

1. **HTML 是压缩的**。`accept-encoding: gzip, deflate, br, zstd` 是 Chrome 的固定头，Caddy 的 `encode` 默认（= `encode zstd gzip`，`Prefer = [zstd, gzip]`，见 `modules/caddyhttp/encode/encode.go` 的 `Provision()`）在 q-factor 相同的情况下按服务端 `prefer` 排序，**会选中 zstd**；如果管理员显式配了 `encode zstd br gzip` 或装了 c-brotli，就会是 br。旧版 Caddy（PR #7772 之前）按客户端 `Accept-Encoding` 里的书写顺序选，Chrome 把 gzip 写在最前，于是回 gzip。
2. 因此**只有能解码，才能发现子资源**；解码不了就退化成"永远只有一个 `GET /`"，preamble 的核心特征（一次页面加载的请求簇）就消失了。

### 5.2 两个候选

| | 方案 A：`URLRequest` 发 preamble | 方案 B：双向流 + 自带解码器 |
|---|---|---|
| body | Chromium 自动解压（E8 实测 zstd→HTML） | 原始字节，需自己解（E9 实测 5 种编码全部可解） |
| 线上请求头 | 与设置逐字一致（E8） | 与设置逐字一致（E2） |
| 强制 QUIC（`QUIC: true` 场景） | ❌ `URLRequestParams` 无此能力 → 必然重演 E4 的连接分裂 | ✅ `-force-quic`（E5） |
| NAK 轮换（`-network-isolation-key`） | ❌ 无此能力 | ✅（E3） |
| 跟随重定向 | 默认会跟随，需额外关掉 | 不跟随（naive 也不跟） |
| 新增依赖 | 无 | `andybalholm/brotli` + `klauspost/compress` |

### 5.3 结论：方案 B（双向流 + 自带纯 Go 解码器）

理由：

1. **QUIC 模式是硬约束**。cronet-go 的 `QUIC: true` 下 CONNECT 走 h3；方案 A 的 preamble 一定走 h2，等于凭空多出一条连接——比"少解析几个子资源"严重得多。
2. **轮换能力绑定在双向流上**（E3），方案 A 会失去 naive 的 NAK 轮换语义。
3. **成本几乎为零**：这两个模块 sing-box 的 `go.mod` 里已经有了（`github.com/andybalholm/brotli v1.1.0 // indirect`、`github.com/klauspost/compress v1.18.0 // indirect`），对 sing-box 这个主要使用者来说最终二进制**不增加任何东西**。cronet-go 独立使用者会多约 **3.4 MB**（实测 windows/amd64：brotli +3.08 MB、zstd +0.80 MB，主要是 brotli 的静态字典表 `static_dict_lut.go` 914 KB + `dictionary.go` 695 KB）。如果维护者在意，可以把解码器放在 `with_preamble` build tag 后面，但默认带上（否则 Caddy 用户直接踩坑）。

### 5.4 解码细节

- 映射：`gzip` → `compress/gzip`；`br` → `andybalholm/brotli`；`zstd` → `klauspost/compress/zstd`；`deflate` → `compress/zlib`；空 / `identity` → 原样。
- `deflate` 的历史坑：Chromium 是**嗅探**的（`gzip_source_stream.cc:110` `STATE_SNIFFING_DEFLATE_HEADER`），Go 侧同样先看头两个字节是不是合法 zlib 头（`(cmf<<8|flg) % 31 == 0 && cmf&0x0f == 8`），是则 `zlib.NewReader`，否则 `flate.NewReader`。
- 多段 `content-encoding`（如 `gzip, br`）按顺序逐层解；遇到未知编码就放弃解析这一块（不影响隧道）。
- **只有根请求需要解码**；子资源的响应体直接丢弃，和原生一致。
- 解压要有上限（防御压缩炸弹）：例如单个根响应解压后最多取 1 MiB 用于解析，超出即停止（原生无上限，因为它把结果丢给 HTML 扫描器且有 64 KiB 分块；我们加个上限不改变可观察行为）。

---

## 6. 方案

### 6.1 总体思路

在 `NaiveClient` 中为每个 engine（即 naive 的 tunnel 槽）维护一份 `preambleState`，用**同一 `StreamEngine`** 发普通 HTTP 请求（GET/HEAD），从而与 CONNECT 流共享同一条连接 / 同一个 session / 同一个 QUIC 连接：

```
                       ┌──────────────── engine[i] (session pool) ────────────────┐
 preambles[i].runFull() │  stream 1: GET /            (preamble)                    │
 preambles[i].startOne()│  stream 2: HEAD /a.css      (preamble)  ── 同一条 TLS 连接 ─┼─► naive / 前置站点
 DialEarly()            │  stream 3: CONNECT          (隧道)                        │
                        └───────────────────────────────────────────────────────────┘
```

关键设计决定（逐条对应"贴近原生"的要求）：

| # | 决定 | 理由 |
|---|---|---|
| D1 | 用 **BidirectionalStream** 而不是 UrlRequest 发 preamble | 与 CONNECT 完全同一条代码路径/连接池；headers 完全可控（E2/E8 实测都没有追加任何头）；能 `-force-quic`（E5）、能按 NAK 隔离（E3）。URLRequest 唯一优势（自动解压）由 D9 补齐 |
| D2 | 首个 CONNECT **等待**完整 preamble 完成 | 对应 naive `DoPreamble → DoPreambleComplete → DoConnect`，否则第一条流就是 CONNECT，前导流量特征消失 |
| D3 | preamble 失败/超时**只记日志**，绝不阻断 CONNECT | 对应 `DoPreambleComplete()` 的注释 "Preamble error doesn't prevent Connect()" |
| D4 | preamble 请求头**只**含 2.4 的浏览器头；不得带 `padding` / `padding-type-request` / `proxy-authorization` / 用户 `extraHeaders` / `fastopen`（唯一允许的内部头是 `-network-isolation-key`，QUIC 模式再加 `-force-quic`） | 对应 `spdy_proxy_client_socket.cc:430-500` 的 preamble 分支 |
| D5 | QUIC 模式下 preamble 流必须带 `-force-quic: true` | E4/E5：否则 preamble 走 h2、CONNECT 走 h3，连接分裂 |
| D6 | 用 `-network-isolation-key` 实现 naive 的 NAK 轮换 | E3：这是唯一能在 Go 侧复现 "换 NAK ⇒ 换 session" 的手段 |
| D7 | 每次 dial（会话未过期时）随机后台发一个已发现请求 | 对应 `StartOne()` |
| D8 | 请求列表只保留 root `/` + 解析出来的子资源，按 path 去重 | 对应 `requests_` |
| D9 | 客户端自带 gzip/deflate/br/zstd 解码（仅用于解析根页面） | 前置真实站点（Caddy `encode`）会回 zstd/br（§5）；E9 验证纯 Go 解码可行 |
| D10 | 用 `params.SetUserAgent(同一个 UA)` 设置引擎 UA | E11：不设时 CONNECT 流会发一个**空的 `user-agent`**；原生 naive 的隧道请求带完整 Chrome UA（`proxy_client_socket.cc:43`）。一行修正，同时与 preamble 的 UA 保持自洽 |

### 6.2 状态与生命周期

```go
// 新增文件 naive_preamble.go
type preambleRequest struct {
    path string
    ext  string // css / js / png / ... ；根请求为 ""
}

type preambleState struct {
    client       *NaiveClient
    streamEngine StreamEngine

    mutex        sync.Mutex
    requests     []preambleRequest // requests[0] 恒为 {"/", ""}
    deadline     time.Time         // tunnel_timeout 到期点（对应 native 的 tunnel.deadline）
    attempted    bool              // 本 epoch 已经跑过（或正在跑）完整 preamble
    running      bool              // 完整 preamble 正在运行
    runningDone  chan struct{}     // 上面的运行结束时关闭，供并发 dial 等待

    epoch        uint64            // NAK 轮换计数 → -network-isolation-key
}
```

`attempted` 的语义要特别注意：**它对应 naive 的 `tunnel.deadline` 而不是“成功”**。native 在 `DoAcceptComplete()` 里是**先** `deadline = now + tunnel_timeout`（并把状态推进到 `kPreamble`）**再**跑 preamble，所以即使 preamble 失败，这个 epoch 也算“用过了”，下一条连接只会 `StartOne()` 而不会再阻塞跑一次完整 preamble。我们的实现必须同样处理，否则 preamble 持续失败会导致每次 dial 都白等一个 `PreambleTimeout`。

每个 `preambleState` 绑定一个 `StreamEngine`（= 一个 engine），生命周期跟随 `NaiveClient`：`Start()` 时创建并放入 `c.preambles[i]`；`doClose()` 里靠 `proxyWaitGroup` 等待所有 preamble goroutine 退出。

轮换键：

```go
// 每个 (engine 槽, epoch) 一个独立 socket pool / session pool
func isolationKey(slot int, epoch uint64) string {
    return F.ToString("https://naive-", slot, "-", epoch, ":443")
}
```

- preamble 启用时，CONNECT 与 preamble 都带这个头（`epoch=0` 即首轮）；
- preamble 关闭时，保持现有行为不变（单 engine 多并发时才用 `https://pool-N:443`，见 `naive_client.go:485-491`），避免影响不启用 preamble 的用户。

### 6.3 请求构造

```go
func (c *NaiveClient) preambleHeaders(index int, r *preambleRequest) map[string]string
func decodeContentEncoding(contentEncoding string, body []byte) ([]byte, error) // §5.4
```

- 方法/路径：`_method`/`_path` 的等价物 = `BidirectionalConn.Start(method, url, headers, priority, true)`，`url = c.serverURL + path`。
- 优先级（int，C API 直接映射 `net::RequestPriority`）：
  `"/"` 或 `.css` 结尾 → `5`(HIGHEST)；`.js` 结尾 → `3`(LOW)；其它 → `2`(LOWEST)。
- 头集合严格按 2.4 复制；`referer = https://<server>/`（GURL 语义：端口为 443 时省略）。
- `user-agent` / `sec-ch-ua*` 在 `NewNaiveClient` 时算一次并缓存（对应 naive 进程内固定）：
  - 主版本号取自 `engine.Version()`（E6），UA 固定为 `Mozilla/5.0 (<unified platform>) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<major>.0.0.0 Safari/537.36`；
  - `sec-ch-ua` 按 2.5 的算法（grease 字符表 + 版本表 + size-2/3 稳定洗牌）；
  - 同步调用 `params.SetUserAgent(ua)`（D10，E11）；
  - 可用 `NaiveClientOptions.PreambleUserAgent string` 覆盖（见 §11 决策 A）。

  跨平台取值（按 `runtime.GOOS`，逐字对应 `user_agent_utils.cc` 的 `GetUnifiedPlatform()` / `GetPlatformForUAMetadata()`）：

  | GOOS | UA 里的平台串 | `sec-ch-ua-platform` | `sec-ch-ua-mobile` |
  |---|---|---|---|
  | windows | `Windows NT 10.0; Win64; x64` | `"Windows"` | `?0` |
  | darwin | `Macintosh; Intel Mac OS X 10_15_7` | `"macOS"` | `?0` |
  | linux | `X11; Linux x86_64` | `"Linux"` | `?0` |
  | android | `Linux; Android 10; K` | `"Android"` | `?0` |
  | ios | `iPhone; CPU iPhone OS 14_0 like Mac OS X` | `"iOS"` | `?0` |

  注意：**naive 客户端从不设置 `kUseMobileUserAgent` 开关**（`net/tools/naive/` 下搜不到任何 mobile 相关参数），所以即使在 Android/iOS 上也发桌面形态的 UA、`sec-ch-ua-mobile: ?0`。这是原生的既定行为，不要"自作主张"改成移动 UA。
- QUIC 模式下所有 preamble 头追加 `-force-quic: true`（D5）。
- 追加内部头 `-network-isolation-key: <isolationKey>`（D6）。

### 6.4 流程伪码

```go
// DialEarly 中，选好 engine 之后：
state := c.preambles[streamIndex]

// beginAttempt 在锁内决定本次该怎么走，并且“先记 deadline 再跑 preamble”（对应 native）：
//   !attempted                     -> (modeFull, epoch, nil)   本 goroutine 跑完整 preamble
//   now > deadline                 -> epoch++、requests 重置、再 (modeFull, epoch, nil)
//   running                        -> (modeWait, epoch, runningDone)  等这次跑完（naive 状态机是串行的）
//   now-lastActivity > idleGrace   -> (modeFull, epoch, nil)   会话已死，等价 naive 的 WillCreateSession()==true（epoch 不变）
//   其他                           -> (modeOne,  epoch, nil)   后台随机发一个
mode, epoch, wait := state.beginAttempt(time.Now())
switch mode {
case modeFull:
    state.runFull(ctx, c.logger)   // read 到 EOF + 解码 + 解析 + 派生子请求；失败只记日志（D3）
    state.finishAttempt()          // running=false; close(runningDone)
case modeWait:
    select {
    case <-wait:
    case <-ctx.Done():
    }
case modeOne:
    c.proxyWaitGroup.Add(1)
    go func() { defer c.proxyWaitGroup.Done(); state.startOne(ctx, epoch) }()
}

headers["-network-isolation-key"] = isolationKey(streamIndex, epoch) // D6
conn := streamEngine.CreateConn(ctx, c.logger, true, false)
conn.Start("CONNECT", c.serverURL, headers, 0, false)
```

`runFull()`：

```
1. index 0：GET c.serverURL + "/"，priority=HIGHEST
2. WaitForHeaders；忽略状态码（对应 :592 "Ignores any response failures"）
3. 循环 Read（裸 BidirectionalConn，禁止套 paddingConn）直到 EOF
4. 按 content-encoding 解码（§5.4）；未知编码/超限则放弃解析
5. 每块内容用 extractPreambleLinks() 抽取 link/script/img
   → 同 host+port 且扩展名在白名单内 → 去重后 append
   → 立刻异步发对应的 GET/HEAD（D8，响应体丢弃不解码）
6. 收尾：lastActivity = now
```

`startOne()`：`rand.Intn(len(requests))` 选一个，发出去、读完丢弃即可（naive 也是读完即弃），成功发出后同样刷新 `lastActivity`。

`extractPreambleLinks()`：照抄 `ExtractLinkAndScriptURLs()`（`preamble_getter.cc:366`）的语义，手写 `<tag attr=...>` 扫描器即可，约 60 行；只认 `link[href]` / `script[src]` / `img[src]`。

这个移植已经做过一次并**与原 C++ 逐字节比对通过**（E16），同时确认了几个必须保留的怪癖（不要"顺手修"，否则就不是原行为了）：

| 输入 | 原生输出 | 说明 |
|---|---|---|
| `<img src>` | 空 | 没有 `=` 就不取 |
| `<img src="">` | `[""]`（一个空串） | 空值会被当成 URL 交给后续流程，最终被“同址去重”丢掉 |
| `<linkage href="/x.css">` | `["/x.css"]` | `StartsWithTag` 是**纯前缀**匹配，没有名字边界（`<scriptfoo src=…>` 同理） |
| `</link>` | 空 | 结束标签以 `/` 开头，不匹配 |
| `<a href="/about.html">` | 空 | 只有 link/script/img 参与 |
| `<!-- <link href="/fake.css"> -->` | 空 | 因为 tag 只取到第一个 `>`，整个注释内容以 `!--` 开头 |
| `<img src="/a>b.png">` | `["/a"]` | 属性值里的 `>` 会把 tag 截断（浏览器不会，原生就这样） |
| `<link href="/a.css" src="/ignored.js">` | `["/a.css"]` | link 只认 `href` |
| `<img data-src="/lazy.png">` | 空 | 只认 `src`，不做懒加载兜底 |

拿到链接后还要走一遍 `DoReadComplete` 的筛选：`root_.Resolve(link)` → host + 端口必须与服务器一致 → `PathForRequestPiece()`（**含 query，只去掉 `#fragment`**，见 `url/gurl.cc:411`；这一点已在实施时修正，原先写成"只取 path"是错的）→ 按该值（含 query）去重 → 扩展名从 `ExtractFileName()`（**不含 query**）取 → 白名单 `{css,js,png,gif,jpg,jpeg,webp,bmp,avif,jxl}`（实测真实页面的 `/about.html` 就是这样被滤掉的，E16）。

### 6.5 对外 API 与依赖变更

```go
type NaiveClientOptions struct {
    // ... 现有字段不动 ...

    DisablePreamble    bool          // 默认 false（= 开启），与原生 naive 一致
    PreambleTimeout    time.Duration // 单条 preamble 请求的超时，**默认 10s**（D3 的兜底，超时只记日志）
    TunnelTimeout      time.Duration // 默认按 GOOS 对齐 naive：Android 600s，其余 1800s（§11 决策 K）
    PreambleUserAgent  string        // 覆盖 UA，默认由 engine.Version() 生成
}
```

`TunnelTimeout` 的默认值取自 `naive_config.h:49-57`（`tunnel_timeout = 600` on Android / `1800` elsewhere），即 Android 上轮换周期是 10 分钟、其它平台 30 分钟。

没有引入任何新的导出类型；`NaiveClient` 只多一个未导出字段 `preambles []*preambleState`。

`go.mod` 新增两个直接依赖（D9）——**默认编进主构建**（不加 build tag；sing-box 的依赖树里本来就有这两个模块，最终二进制零增加）：

```
require (
    github.com/andybalholm/brotli  v1.2.6
    github.com/klauspost/compress  v1.20.1   // 只用 /zstd 子包
)
```

### 6.6 QUIC / ECH / 并发 兼容性

- **QUIC**：唯一需要额外动作的地方是 `-force-quic`（D5），其余完全一致。
- **ECH**：preamble 与 CONNECT 走同一个 engine、同一个 NAK，ECH 配置一致，无需特殊处理。
- **并发**：`concurrency>1` 时每个 engine 一个 `preambleState`；单 engine 多并发（`TestForceSingleEngine`）时再叠加槽位号，隔离键变成 `naive-<slot>-<epoch>`，与现有 `pool-<i>` 语义等价。
- **UDP/Fast Open**：preamble 不影响；`fastopen` 头按原实现也不加在 preamble 上。

---

### 6.7 会话存活判定（实测后的修正）

naive 用 `WillCreateSession()` / `CanUseExistingSession()` **真实查询 session pool** 来决定“跑完整 preamble”还是“StartOne”。cronet-go 的 C API 没有查询 session pool 的能力，只能用近似。E12/E13 给出了近似所需的关键参数：

| 协议 | 空闲多久后会话消失 | 依据 |
|---|---|---|
| h2 | **≥ 10 分钟**（实测 600s 仍复用同一 session） | E12 |
| QUIC | **约 30 秒**（`max_idle_timeout 30000`，双方一致） | E13 |

因此 `preambleState` 维护一个 `lastActivity`（每次 dial、每条 preamble 请求完成时刷新），并在决定分支时加一条：

```go
const (
    preambleQUICIdleGrace = 20 * time.Second            // < 30s，留一点安全边距（E13）
    preambleTCPIdleGrace  = 10 * time.Minute            // 实测下限（E12）
)
```

超过 grace 就当作“会话已死”→ 跑完整 preamble，**但不动 epoch**（对应 naive：NAK 不变，只是池里没有可用会话）。

注意两个常数与 `TunnelTimeout` 的关系：Android 上 `TunnelTimeout=600s`，而 `beginAttempt` 的判定顺序是 `deadline 轮换` 先于 `idleGrace`，因此 Android 上 TCP 的 idleGrace 实际不会生效（不会错，只是多余）。

意义：QUIC 场景下如果没有这条判定，每个“空闲 30s 后再来的连接”都会在一个**新建的 QUIC 会话**上先发一个随机子资源（前置站点场景），而不是像 naive 那样从头拉一次页面。

已知局限（见 §9）：活跃隧道会保持会话存活，但我们不跟踪隧道活跃度——只会导致“多跑一次完整 preamble”，不会产生错误行为。

---

## 7. 备选方案与取舍

| 方案 | 结论 |
|---|---|
| 用 `URLRequest` 发 preamble | ❌ 能白拿 Chromium 的解压（E8），但 `URLRequestParams` 既不能强制 QUIC 也不能设 NAK：QUIC 模式下必然分裂出两条连接（E4），且失去轮换手段（E3）。仅当"确定不用 QUIC、且不想引入解码依赖"时才可作为退路 |
| 只发根请求，不做 HTML 解析 | ❌ 与原生行为不一致：前置真实站点时原生会连带 css/js/img，请求数量与优先级分布都不同（指纹差异）。实现成本仅约 60 行 + 解码器，值得做 |
| preamble 在 `Start()` 里后台预热，首个 dial 不等待 | ❌ 会让首个 CONNECT 抢先发出，正好丢掉 preamble 最核心的"前导页面加载"特征。（若为了延迟可做成可配置，但默认必须等待。） |
| 轮换用 `CloseAllConnections()` | ❌ 会掐断所有活跃隧道；`-network-isolation-key` 已在 E3 中验证可用，且语义与 naive 的 NAK 一一对应。 |
| 复刻 naive 的 1 分钟 idle 清理定时器 | ❌ cronet-go 侧没有"隧道对象"，Cronet 自己会回收空闲 socket；轮换已限制单连接寿命。见 §9。 |
| 每个 dial 都发完整 preamble | ❌ 流量过大。原生只在会话建立/轮换时发完整 preamble，平时每次 dial 只 `StartOne()`。 |
| 只解 gzip，不解 br/zstd | ❌ Caddy 默认给 zstd（§5.1），会直接退化成"只有一个 GET /" |

---

## 8. 实施步骤（建议顺序）

1. `naive_preamble.go`：`extractPreambleLinks()` + UA/sec-ch-ua 生成 + `decodeContentEncoding()`（三个纯函数，先写单元测试）。
2. `go.mod` 加 brotli / klauspost-compress（仅 zstd 子包会被链接）。
3. `preambleState` + `runFull` / `startOne` / `beginAttempt`（含 `§6.7` 的 idleGrace 分支），用 `Engine.StreamEngine()` 直连，先在 E1/E9/E10 的实验程序里跑通。
4. `NaiveClient` 接线：字段、options、`DialEarly` 里的触发点与 `-network-isolation-key` 注入；QUIC 分支加 `-force-quic`；`startEngine()` 里 `params.SetUserAgent(ua)`（D10）。
5. `Start()` 里按 engine 建状态；`doClose()` 里用 `proxyWaitGroup` 收尾；preamble 流被取消（`Close()` 路径）归一为 warning。
6. 日志：`logger.DebugContext` 打 `preamble <path>`（naive 是 `LOG(INFO)`），`logger.WarnContext` 打 preamble 失败原因。
7. 补测试（见 §10）。

---

## 9. 已知偏差（有意保留）

1. **不实现 naive 的 idle 清理定时器**（`CleanUpIdleConnections`）：`idle_timeout` / 超龄隧道的主动断开交给调用方与 Cronet 自身；session 寿命已由 epoch 轮换限制为 ≤ `TunnelTimeout`。
2. **用 `lastActivity` + idleGrace 近似 naive 的 session pool 查询**（§6.7）：C API 无法查询池；近似只会导致偶尔多跑一次完整 preamble。
3. **子资源解析粒度**与原生一致（只解析最后一个分块，可能漏掉跨块标签），不做改进。
4. `ext == ".js"` 这个原生死代码分支不复制；实际优先级按 `.js` 后缀判断（与 `spdy_proxy_client_socket.cc:487` 的行为一致，即原生真正生效的行为）。
5. **HTML 解析加了 1 MiB 解压上限**（§5.4），原生无上限；正常页面远小于此。
6. 额外流量开销：每条连接 1 个额外请求（原生同样如此），可用 `DisablePreamble` 关闭。
7. 二进制体积：独立使用者 +3.4 MB（§5.3）。
8. 与本主题相邻的两处历史差异均已修：CONNECT 的空 `user-agent`（D10）与缺失的 `padding-type-request: 1`（§13.4），CONNECT 的头顺序也已对齐原生。

---

## 10. 测试方案

### 10.1 端口冲突处理（重要）

`test/main_test.go:37` 把 naive 服务端口写死为 `naiveServerPort = 10443`，而本机 10443 已被用户的 sing-box 占用，直接跑 `make test` 会冲突/误连。实施时建议：

- 把 `naiveServerPort` 改为可配置：默认读环境变量 `CRONET_TEST_NAIVE_PORT`，未设置时回落到 `10443`；
- 或者本地测试统一使用 `10444/10445`（本文实验即如此）。

另外，Caddy 前置场景需要一个"会 br/zstd 压缩的站点"，集成测试里可用 `net/http` + `klauspost/compress/zstd` + `andybalholm/brotli` 起一个临时 TLS 站点来模拟（这两个依赖届时已在 `test/go.mod` 中）。

### 10.2 用例

| 用例 | 内容 | 判定 |
|---|---|---|
| T1（纯单测） | `extractPreambleLinks`：用 E16 里那 14 个用例（含前缀匹配、注释、`>` 截断、空值等怪癖）+ 真实页面 HTML | 与原生 `ExtractLinkAndScriptURLs` 输出完全一致（设计阶段已用 g++ 编译的原函数逐字节对过，可直接拿那 14 条作为断言） |
| T2（纯单测） | UA / `sec-ch-ua` 生成，major 取 150/153/154/155 | UA 等于 `Mozilla/5.0 (Windows NT 10.0; Win64; x64) … Chrome/<major>.0.0.0 Safari/537.36`；`sec-ch-ua` 等于 §2.5 表里那几个值（已经与原 C++ 对过，E17） |
| T3（单测） | `decodeContentEncoding`：zstd / br / gzip / zlib-deflate / raw-deflate / identity / 未知编码 / 多段编码 | 全部还原原文；未知编码安全返回错误 |
| T4（单测） | `-network-isolation-key` / `-force-quic` 头构造 | 头名与取值符合 6.3；preamble 头集合中不含 `padding`/`proxy-authorization`/用户 `extraHeaders` |
| T5（集成） | sing-box naive inbound（临时端口），开 NetLog，`DialContext` 一次 | netlog 中存在 `method:"GET"` 的 BIDIRECTIONAL_STREAM，且与随后的 CONNECT 流**同一个 HTTP2_SESSION source id**、GET 的 `stream_id` 更小 |
| T6（集成） | 同上，`QUIC: true` | 全部流在同一个 `QUIC_SESSION`，且无 `TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET` |
| T7（集成） | 服务器不可达 / 立即 RST | preamble 失败仅告警，`DialContext` 仍能成功建立隧道（验证 D3） |
| T8（集成） | 临时前置站点：根页面分别以 zstd / br / gzip / deflate 应答，内含 `<link href=/a.css>` | netlog 中在 CONNECT 之前出现 `HEAD/GET /a.css` 流（验证 D9 + 子资源发现） |
| T8b（集成，建议作为主用例） | **直接用 klzgrad Caddy（用户已编译在仓库根目录的 `caddy.exe`）**：`forward_proxy{basic_auth;probe_resistance}` + `encode` + `file_server`（真实站点）监听 127.0.0.1 的临时端口 | 同 E14：preamble 根 + 子资源 + CONNECT **共用同一个 `HTTP2_SESSION`**；隧道数据能回环；换 isolation key 后新建 session；服务端 access log 中 preamble 请求无 `Padding`/`Proxy-Authorization` |
| T9（集成） | `DisablePreamble: true` | netlog 中除 CONNECT 外无其他流，且行为与改动前一致（回归） |
| T10（集成） | `QUIC: true`，首次 dial → 空闲 > 30s（会话已死）→ 第二次 dial | 第二次 dial 前存在 `HTTP2/QUIC_SESSION` 重建，且**先**出现根请求（`GET /`）而非随机子资源（验证 §6.7 的 idleGrace 分支） |
| T11（集成） | 任意一次 `DialContext` | netlog 中 CONNECT 流的头部包含 `user-agent: Mozilla/5.0 …`，且不存在空值 user-agent（验证 D10 / E11） |

集成测试沿用 `test/main_test.go` 现有的 sing-box 启动封装（`startNaiveServer`），把端口参数化即可。Caddy 侧的两个硬性配置条件（否则用例会直接失败，不要误判为客户端 bug）：

- `forward_proxy { basic_auth …; probe_resistance }`：缺 `probe_resistance` 时 preamble GET 会得到 **407**（无 `hosts` 时非 CONNECT 请求不会 fallthrough 到 `file_server`，见 §4.1）；
- 如果要给 Caddy 喂一个回环地址的测试目标，需要 `acl { allow 127.0.0.1/32 }`（默认 ACL 拒绝回环/内网）。

---

## 11. 评审意见的结论

### A. UA 的取值要不要跟"前置站点"对齐？

**当时的问题表述不清楚，澄清一下**：preamble 请求里的 `user-agent` / `sec-ch-ua` 是发给前置真实网站看的，问题是"该填什么值"。选项无非是：(a) 固定成 Chrome UA，(b) 做成可配置，让用户跟自己的实际客户端保持一致。

**结论**：默认 (a) —— 用 `Chrome/<major>.0.0.0`，其中 major 取自 `engine.Version()`（E6）。理由：原生 naive 客户端也是这么生成的（§2.5），而且 Chrome 访问同一个站点时用的就是这套 UA，不存在"和站点不匹配"的问题。同时保留 `NaiveClientOptions.PreambleUserAgent` 覆盖项，供自定义过 UA 的用户（对应 naive 的 `--user-agent`）保持一致。**无需再决策，按此实现。**

### B. `idle_timeout` 是否暴露？

**结论**：不暴露。cronet-go 没有 naive 那样的"隧道对象"可以断开，暴露一个改不动的旋钮没有意义。单连接寿命已经由 `TunnelTimeout`（epoch 轮换）限制。见 §9 第 1 条。

### C. `-force-quic` 有没有替代方案？

**澄清**：QUIC 模式下 naive 服务器同时提供 h2 和 h3，客户端要保证 preamble 与 CONNECT 落在**同一条 QUIC 连接**上，否则一个页面加载会开两条连接（E4 实测）。`-force-quic: true` 是 `net::BidirectionalStream` 独有的内部头（`bidirectional_stream.cc:219`），作用是把这次请求钉到 QUIC；它是目前唯一能做到这一点的开关（`URLRequestParams` 没有等价物）。

**结论**：保留 D5，没有替代方案；这也是不用 `URLRequest` 发 preamble 的决定性理由之一。

### D. `concurrency>1` 时是否每个 engine 都跑完整 preamble？

**结论**：和原生保持一致 —— naive 的 `tunnels_[next_id_ % concurrency_]` 每个槽各自维护 deadline、各自首连跑完整 preamble（`naive_proxy.cc:159-176`），本方案按 engine 一一对应复刻，不做"仅槽 0 预热"之类的简化。

### E.（新增）内容编码

已从"不解码 br/zstd"改为**客户端自带纯 Go 解码器**（D9 / §5）。原因：用户的 `caddy forwardproxy + file_server` 部署下根页面就是 zstd/br，不解码就等于没有子资源发现。代价与缓解见 §5.3。

### F.（新增）CONNECT 流的 `user-agent` 是空的

E11 发现：cronet-go 现在发出去的 CONNECT 请求带一个 `user-agent: `（空值），因为 libcronet 里没有任何 UA 模板串（E7），而双向流的请求头会把 `HttpUserAgentSettings::GetUserAgent()` 的结果无条件塞进去。原生 naive 的隧道请求是带完整 Chrome UA 的（`net/http/proxy_client_socket.cc:43`）。

**结论**：要修，而且顺理成章——preamble 本来就需要一个 UA 字符串，`params.SetUserAgent(ua)` 一并搞定（D10），两者保持一致。这是独立于 preamble 的既有指纹差异。
### G.（新增）同一个 engine 上并发 dial 怎么办？

naive 的 accept 状态机是**串行**的，所以第二个连接会自然排在第一个的 preamble 后面。我们这里是并发调用，不能把第二个连接"放行"去抢跑（那会让它在 preamble 建立会话之前就发 CONNECT，甚至开出第二条连接）。

**结论**：`running` 为 true 时，并发 dial **等待**这一次完整 preamble 结束（`runningDone` channel，带 `ctx` 超时兵底），而不是直接跳过去发 `StartOne`。已按此更新 §6.4 伪码。

### H.（新增）会话存活怎么判？

naive 查 session pool，我们查不到。实测（E12/E13）：h2 空闲 10 分钟仍在，QUIC 空闲 30 秒就断。

**结论**：用 `lastActivity + idleGrace` 近似（QUIC 20s / TCP 10min），超时就重跑完整 preamble（epoch 不变）。不做"ping 保活"（原生没有，反而会制造额外流量），也不去猜池。详见 §6.7。

### I.（新增）真实前置站点的两个配置前提（E14）

实测（§4.1）确认了两件之前没写进方案的事：

1. **preamble 请求必须不带 `Proxy-Authorization`**（原生也是这么做的），而服务器侧的 `forward_proxy` 必须开 **`probe_resistance`**，否则 preamble GET 会被回 407、拿不到任何 HTML。客户端不需要为此加选项，但要保证：**407/403 等非 200 响应不报错、只记日志**（D3 已覆盖），并且不要因为拿到 407 就去重试带鉴权的版本（原生不重试）。
2. forwardproxy 默认 ACL **拒绝回环/内网目标**，且 CONNECT 是 Fast Open（先 200 再连），失败时表现为“200 之后立刻 RST”，排查时要能区分。

### 定稿：最终选项与边界（已拍板）

以下五项是本轮评审的最终结论，实现时直接按此做，不再展开讨论：

| # | 项 | 定稿值 | 依据 |
|---|---|---|---|
| K1 | `PreambleTimeout` 默认 | **10s** | 评审决定（原拟 15s）；仅用于 epoch 内第一条连接，超时只记日志不阻断 |
| K2 | `TunnelTimeout` 默认 | **按 GOOS 对齐 naive：Android 600s，其余 1800s** | `naive_config.h:49-57` |
| K3 | brotli+zstd 依赖 | **默认编入主构建（不加 build tag）** | 评审决定；sing-box 依赖树已有，最终二进制零增加 |
| K4 | CONNECT 的空 `user-agent` | **一并修**（`params.SetUserAgent(ua)`，D10） | 评审决定；E11/E14 实测证据 |
| K5 | 空闲 grace | **保持**（QUIC 20s / TCP 10min） | 评审决定；E12/E13 实测值 |

上面五条加上 A–J，本方案已无待决策项。**仍未实施**：本文档是唯一交付物。
---

## 12. 实施记录（v7）

### 12.1 改动的文件

| 文件 | 改动 |
|---|---|
| `naive_preamble.go`（新增，~470 行） | client hints（UA/sec-ch-ua/平台）、HTML 扫描器、内容解码、`preambleState` 状态机（`beginAttempt`/`runFull`/`startOne`/`send`） |
| `naive_client.go` | 4 个新选项；`preambles`/`hints` 等字段；`startEngine()` 里 `params.SetUserAgent(...)`（读取**启动前**即可用的 `engine.Version()`，D10）；`Start()` 里按 slot 建状态；`DialEarly()` 里触发 preamble 并注入 `-network-isolation-key` |
| `naive_preamble_test.go`（新增） | 单元测试 T1–T4（含 E16/E17 的对拍期望值） |
| `go.mod` / `go.sum` | `andybalholm/brotli v1.2.6`、`klauspost/compress v1.19.0`（v1.20 要求 go 1.25，为保持 `go 1.24.0` 而降级） |
| `test/preamble_test.go`（新增） | 集成测试 T5–T9、T8b |
| `test/main_test.go` | `naiveServerPort` 支持 `CRONET_TEST_NAIVE_PORT` 覆盖（§10.1），并同步替换配置里的 `listen_port` |
| `test/quic_test.go` | ECH/DNS 延迟用例加 `DisablePreamble: true`（见 12.3） |
| `test/engine_test.go` | 修正过期的版本号断言 `150.0.7871.63` → `154.0.8037.49`（与 `lib/windows_amd64/libcronet.go` 对齐；**这是本次改动前就已存在的失败**） |

### 12.2 实施中发现并修正的三处偏差

1. **图片子资源要用 `HEAD`，不是 `GET`。** 第一版 `send()` 对所有子资源都发 GET；真实 Caddy 的 NetLog 显示 `/img/logo.png` 是 `GET`，与 naive 的 `AddHeaders()`（只有 css/js 用 GET）不符。已加 `preambleMethod()` 并补单测。
2. **子资源请求必须并发发出、不等待。** 第一版在 `runFull()` 里同步逐个发送，会把隧道的建立推迟 N 个往返（naive 是 fire-and-forget）。已改为每个子请求一个 goroutine，并计入 `proxyWaitGroup`。
3. **`PathForRequestPiece()` 含 query**（§2.3/§6.4 已同步修正）：去重键与请求路径都保留 query，只有 `#fragment` 被去掉；扩展名仍从**不含 query** 的 `ExtractFileName()` 取（例如 `/style.css?v=1` → GET + css 头，但优先级按整串判断为 LOWEST）。

### 12.3 行为变化带来的测试适配

- **ECH/DNS 延迟用例**：`TestNaiveQUICDomainNon443ECHHTTPSDNSDelayAffectsHandshake` 断言"握手耗时 ≥1.5s"，而默认开启的 preamble 会**先把那次 HTTPS/ECH 查询消耗掉**（native naive 同样如此，因为 preamble 走的是同一个 resolver）。该用例已显式 `DisablePreamble: true` 以保持它原本要测的语义。
- **端口冲突**：本机 10443 已被用户的 sing-box 占用，测试用 `CRONET_TEST_NAIVE_PORT=10444` 运行；默认值仍是 10443，不影响 CI。

### 12.4 验证结果

| 验证 | 结果 |
|---|---|
| `go build ./...`（windows/amd64 purego；linux/amd64 purego 交叉编译） | 通过 |
| 单元测试（`go test -tags with_purego .`，11 个用例） | 全部通过 |
| 新集成测试（`test/preamble_test.go`，5 个测试 / 9 个用例） | 全部通过 |
| **完整测试套件**（`CRONET_TEST_NAIVE_PORT=10444 cronet.test.exe -test.run '.*'`，Caddy 二进制在 PATH 上） | **41 PASS / 0 FAIL / 0 SKIP** |
| 真实 klzgrad Caddy（`caddy.exe` + `forward_proxy{probe_resistance}` + `encode` + `file_server`） | 端到端通过：`GET /`（200 + zstd）→ 发现并请求 `/style.css`、`/app.js`、`HEAD /img/logo.png` → CONNECT 带 padding/auth → 隧道数据回环成功；全过程 **1 条 h2 连接**（`TCP socket pool = 1`，五条流同属一个 `HTTP2_SESSION`），且 CONNECT 的 `user-agent` 是完整 Chrome UA（D10 生效） |
| 真实 Caddy + QUIC（E15 方式） | preamble 与 CONNECT 共用唯一 `QUIC_SESSION`，0 个 TCP socket |

### 12.5 对应关系（§10.2 用例 → 实际测试）

| 计划用例 | 实现位置 |
|---|---|
| T1 HTML 抽取 / T3 内容解码 / T4 头与优先级 + D10 头 | `naive_preamble_test.go` |
| T2 UA / sec-ch-ua（150/153/154/155） | `naive_preamble_test.go: TestBrandMajorVersionList`、`TestNewClientHints` |
| T5 同会话 + 顺序 / T7 preamble 失败不阻断 / T11 CONNECT 的 UA | `test/preamble_test.go: TestNaivePreamble` |
| T6 QUIC 同会话 | `TestNaivePreambleQUIC` |
| T8 前置站点 + 子资源发现（zstd/br/gzip/deflate/identity 五个子用例） | `TestNaivePreambleFrontingSite` |
| T9 `DisablePreamble` 回归 | `TestNaivePreambleDisabled` |
| T8b 真实 klzgrad Caddy 端到端 | `TestNaivePreambleCaddy`（用 `CRONET_TEST_CADDY` 或 PATH 里的 caddy，找不到则自动 skip） |

---

## 13. 与原生 naive 的指纹一致性对照（v8）

> 问题：这个 preamble 的指纹和原生 naive 一样吗？答案：**在可观察的维度上等价，但有三处已知差异**（其中两处在实施/复核阶段已修，第三处是"我们更完整"而非更差）。

### 13.1 已对齐（逐字或逐语义，均有源码对拍或实测）

| 维度 | 依据 |
|---|---|
| 请求集合与筛选规则（同 host+effective port、扩展名白名单、按含 query 的 path 去重） | 与 C++ 逐字节对拍（E16）+ 真实页面实测 |
| 请求方法（css/js = GET，其余 = HEAD）与优先级（`/`、`.css` → HIGHEST；`.js` → LOW；其余 LOWEST） | `preamble_getter.cc` + `spdy_proxy_client_socket.cc:487` |
| 请求头内容（含 UA、`sec-ch-ua`、平台串、`priority`、`referer` 等逐字一致） | E17（brand 列表算法对拍 100..199 全等）+ E14 服务端 access log |
| **请求头顺序** | naive 的 `HttpRequestHeaders` 是**插入序**（`SetHeaderInternal` 用 `emplace_back`，不排序），故线上顺序 = `AddRootHeaders`/`AddHeaders` 的书写顺序且每次固定。已改为按该顺序显式传入（`HeaderField`），并在 NetLog 上断言（v8 新增，见 13.3） |
| preamble 不带 `padding` / `padding-type-request` / `proxy-authorization` / 用户 `extraHeaders` / `fastopen` | `spdy_proxy_client_socket.cc:430-500`；E14 服务端可见 |
| 忽略响应状态码、失败不阻断 CONNECT、失败后同一 epoch 不再阻塞重试 | `DoPreambleComplete` / `naive_proxy.cc:144-180` |
| 首连跑完整 preamble 并阻塞 CONNECT；会话存活期每次连接只发一个随机请求；到期轮换（epoch++ → 换 isolation key） | `naive_proxy.cc` 状态机；sing-box 实测第二条连接只发一条 `GET /app.js` |
| 子请求先于 CONNECT 上线 | v8 修正（见 13.3）；Caddy 端到端连续 3 次断言通过 |
| 解码行为（identity/unknown 原样透传、多段编码逆序解、deflate 先 zlib 后 raw） | `filter_source_stream.cc:118-160` |

### 13.2 已知差异（诚实列出）

1. **HTTP 缓存**：naive 的 preamble 走 `LOAD_NORMAL`（可能命中 HTTP 缓存），我们的双向流不经过缓存。首次访问（无缓存）无差异。
2. **CONNECT 请求本身（不属于 preamble）**：见 13.4 的实测结论。

已经**消失**的差异（不再存在）：

- ~~子请求发起时机~~：已按 naive 实现为**流式分块解析**（见 13.3 第 3 条）。
- ~~解析粒度~~：之前文档里写的“naive 每块只保留最后一块、跳块标签会漏”是**错的**。真相是 `DoReadComplete` 先 `last_content.append(new_data)` 再解析、最后 `last_content = new_data`，即每个窗口是 **上一块 + 当前块**（64KB 一块）。因为完整标签必然会完整落在某个窗口里，它其实**不会漏**。我们已按同样语义实现（`window = lastContent + chunk`，只保留当前块），两边行为一致。

### 13.3 为对齐指纹做的三个修正

1. **请求头顺序**：新增有序头路径（`HeaderField` + `BidirectionalStream.startHeaders` + `BidirectionalConn.StartWithHeaders`），preamble 按 `AddRootHeaders`/`AddHeaders` 的书写顺序传入。公开的 map 版 `Start` 行为未变（避免影响 CONNECT 等既有调用）。
2. **子请求与 CONNECT 的顺序**：`runFull` 现在**同步**把发现的子请求排队（`Start` 只是把请求投递到网络线程，不阻塞），随后才由 `DialEarly` 建 CONNECT，因此子请求的 HEADERS 帧**必定先于** CONNECT 上线（与 naive 一致）；响应体的读取/丢弃仍在后台 goroutine 里。
3. **流式分块解析（边读边发）**：根页面的读取改为 64 KiB 分块（`preambleReadSize`），解码器改成流式链（`preambleReader`/`newPreambleDecoder`，gzip/zlib/raw-deflate/br/zstd，deflate 先试 zlib 再回退 raw），每块按 naive 的窗口语义解析并**立即**发起新发现的请求。因此页面还在传输时，它内部的资源就已经开始被请求（与原生一致），而不是等整页读完。上限 1 MiB 仍由 `io.LimitReader` 约束。

两项都有断言：`TestPreambleHeaderOrder`（单测，root/css/js/image/QUIC 五个序列）与 `TestNaivePreamble`/`TestNaivePreambleCaddy`（NetLog 上的实际线上顺序 + "子请求在 CONNECT 之前"）。

### 13.4 CONNECT 请求的头部（实测，供决定是否调整）

从源码推出的 naive CONNECT（h2）常规头顺序：

```
padding, padding-type-request, [用户 extra_headers], user-agent, proxy-authorization
```

来源：`DoCalculateHeadersComplete` 先 `MergeFrom(proxy_delegate_headers_)`（= `OnBeforeTunnelRequest` 的 `padding` → `padding-type-request` → 用户头，`fastopen` 在发送前被移除）；随后 `DoSendRequest` 调 `BuildTunnelRequest()`，后者按序 `SetHeader(host)`（h2 丢弃）、`SetHeader(proxy-connection)`（h2 丢弃）、`SetHeader(user-agent)`，再 `MergeFrom(authorization_headers_)`（= `proxy-authorization`）。`HttpRequestHeaders` 是插入序（`SetHeaderInternal` 用 `emplace_back`），所以这个顺序是**确定**的。

我们当前的情况（实测）：顺序是 Go map 随机；并且**不发 `padding-type-request`**；`user-agent` 由 net 追加在最后。

实测结论（E18，用带 `user-agent: EXPLICIT-UA/1.0` + 引擎 UA `ENGINE-UA/1.0` 的 CONNECT 验证）：

- 显式传入的 `user-agent` **不会被引擎 UA 覆盖**，也不重复，位置由我们决定 → 也就是说 CONNECT 的头顺序**完全可控**（走 13.3 第 1 条的有序路径即可）；
- `padding-type-request` 会原样上线（没有任何层会剥离它）。

**已实施**：`DialEarly` 改用有序头路径，按 `[padding, padding-type-request, 用户 extraHeaders(按名排序), user-agent, proxy-authorization]` 发送（内部头 `-force-quic`/`-network-isolation-key` 追加在后，反正被 net 消费、不上线），并补上原缺失的 `padding-type-request: 1`（cronet-go 实际只支持 variant1）。NetLog 断言见 `TestNaivePreamble`：CONNECT 的线上头序列必须等于 `padding, padding-type-request, user-agent, proxy-authorization`，且 `padding-type-request` 的值为 `1`。

**已核实（降低风险）**：`padding-type-request` 这个头 **sing-box 的 naive inbound 和 klzgrad 版 Caddy 都不读**（两者都只看 `padding` 头），所以加上它不会改变服务端行为，纯粹是“更像原生”。

**一个无法完美对齐的点**：`NaiveClientOptions.ExtraHeaders` 是 Go 的 `map[string]string`，在 API 边界就丢掉了顺序，所以用户自定义头只能做**确定性排序**（按名字），无法与 native 的“配置书写顺序”逐位对应；要完全对应必须把该选项改成有序列表，那是破坏性的 API 变更（下游 sing-box 传的就是 map），不建议。

### 13.5 “纯 Go 实现会不会让 TLS 指纹变掉？”——不会（附实测）

**preamble 没有使用 Go 的 TLS/HTTP 栈。** 客户端路径（`naive_preamble.go` / `naive_client.go` / `naive_conn.go` / `bidirectional_conn.go`）里没有 `crypto/tls`、`net/http`、`http.Transport`；preamble 只通过 `StreamEngine` → `BidirectionalStream` 走 libcronet 自己的网络栈（BoringSSL / QUICHE / Chromium net），和 CONNECT 完全相同——这也正是"共用同一条会话"的前提。Go 只负责：编排（何时发什么）、HTTP 头字符串、HTML 扫描、gzip/br/zstd 解码。`crypto/tls` 只出现在测试文件里（测试用的假前置站点是 Go 服务端，与服务端指纹有关、与客户端无关）。

实测（NetLog，同一台机器，`TestNaivePreamble` vs `TestNaivePreambleDisabled`）：

| 指标 | preamble 开 | preamble 关 |
|---|---|---|
| `SSL_CONNECT`（同一次握手的 begin/end） | 2 | 2 |
| `TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET` | 1 | 1 |
| `HTTP2_SESSION` | 1 | 1 |
| 承载所有流的 h2 session | 唯一的 src 21 | 唯一的 src 21 |

即：**开了 preamble 之后仍然只有一次 TCP 连接、一次 TLS 握手**（preamble 的 GET/子资源与 CONNECT 的全部 h2 帧共用它），所以不存在"多出来一个 Go TLS 指纹"。

把两次握手的 ClientHello 解出来对比（记录于本节）：

- cipher suites：`1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035` + 一个 GREASE（两个 run 完全一致，只有 GREASE 取随机值不同）——这是 Chromium/BoringSSL 的固定列表；
- extensions：含 **ALPS(17613)**、**ECH(65037)**、`compress_certificate(27)`、`renegotiation_info(65281)`、两个 GREASE，以及 Chromium 的**每连接扩展顺序随机化**（两个 run 的扩展**集合**相同、**顺序**被置换——这正是 Chromium 的抗指纹手段之一）；
- Go 的 `crypto/tls` 不会发 ALPS，不发 GREASE，也不做扩展置换，cipher 列表也不同 ⇒ 如果真用 Go 栈，指纹必然不同；而这里不是。

推论：preamble 的**客户端 TLS/h2 指纹 = 该 libcronet 构建（= 对应 Chromium 版本）的指纹**，与原生 naive（同样是 Chromium 栈）在同一 Chromium 版本下一致；会随 Chromium 版本变化，所以要与原生客户端对齐就该保持两者版本一致（UA / `sec-ch-ua` 也是运行时从 `engine.Version()` 推导，自动跟随）。

唯一由 Go 影响线上内容的部分是 **h2 HEADERS 帧里的头名/头值/头顺序**，这部分已按原生逐字对齐（E16/E17 + §13.3）。

---

## 14. 代码评审问题的处理（v9）

外部评审提了 6 条，逐条核对与处理结果：

| # | 问题 | 结论 | 处理 |
|---|---|---|---|
| 1 | `math/rand` 全局源默认种子为 1，`StartOne` 随机是确定性的 | **前提不成立** | Go ≥1.20 起全局源已**自动随机播种**（实测：三个进程 `rand.Intn` 序列各不相同），仓库里也没有任何 `rand.Seed`。`naive_conn.go` 用的是同一个 `math/rand`；为保持与仓库一致未改。（`math/rand/v2` 等价，可换但不必要。） |
| 2 | `preambleModeWait` 路径吞掉 `ctx` 取消，取消后仍继续建 CONNECT | **成立** | 等待分支结束后统一检查 `ctx.Err()`，非 nil 直接 `return nil, err`。（`runFull` 自身的失败（400/超时/解码错）仍不阻断 CONNECT，见 D3；只有**父 ctx 被取消**才中止。） |
| 3 | `startOne()` / `addDiscovered()` 内部再取 `epochSnapshot()`，轮换窗口内可能与 CONNECT 的 epoch 不一致 → 分裂成两条连接 | **成立**（需经 #4 的路径触发） | 改为**参数透传**：`DialEarly` 把 `beginAttempt` 返回的 epoch 传给 `runFull(ctx, epoch)` → `addDiscovered(html, epoch)` 与 `startOne(epoch)`；`epochSnapshot()` 已删除。 |
| 4 | `beginAttempt` 先判 deadline 再判 `running`：deadline 到期时正在跑的 Full 会被第二次 Full 覆盖 `runningDone` | **成立**（TunnelTimeout 配得比 preamble 还短时） | 把 `if s.running` 提到最前（语义不变：跑着的时候后来者本来就该等）。新增断言：deadline 已过期但仍在运行 → 必须 `modeWait` 且 epoch **不变**。 |
| 5 | `TestExtractPreambleLinks` 用 `[...]` 拼接断言，`[""]` 与 `[]` 无法区分，掩盖了 `<img src="">` 的怪癖 | **成立** | `formatList` 改为 `%q` 输出，断言改为 `["/a.css"]` / `[""]` 形式；`<img src="">` 现在真的锁住“返回一个空串”。 |
| 6 | `TestAddDiscovered` 把筛选逻辑抄了一遍，函数漂移测不出来 | **成立** | 抽出纯函数 `filterPreambleLink(root, known, link) (preambleRequest, bool)`，`addDiscovered` 调用它；测试改为直接测该函数（13 个用例：同源/跨站/跨端口/相对路径/query 保留/扩展名白名单/去重/根路径/非 http），不再复制逻辑。 |

回归：单元测试 13 项全过；完整集成套件 **42 PASS / 0 FAIL / 0 SKIP**（windows/amd64 purego，含真实 klzgrad Caddy 端到端、QUIC、streaming、头顺序断言）；linux/amd64 purego 交叉编译通过。
