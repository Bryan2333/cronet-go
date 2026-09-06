# Naiveproxy Cronet Porting Instruction

## Objective

`naiveproxy` 使用 Chromium 网络栈，源码与 Chromium 版本强绑定。构建
`cronet-go` 时，先选择跟进目标 Chromium 的 naiveproxy 源码，再把 Cronet
支持移植进去。

最终结果应为：

```text
目标 naiveproxy 源码 + Cronet 集成改动 + 目标 Chromium API 适配
```

## Source Roles

不要按仓库名称混淆用途：

```text
<upstream>       klzgrad/naiveproxy，官方 naiveproxy 基线
<cronet-fork>    SagerNet/naiveproxy，包含 cronet-go 集成
<target-fork>    跟进目标 Chromium 的第三方 naiveproxy fork
```

`<target-fork>` 是最终 Chromium 源码来源，`<cronet-fork>` 只提供 Cronet
集成改动，`<upstream>` 用来隔离和理解两类改动。不要把 Cronet fork 的
Chromium 源码覆盖到 target，也不要直接合并整个 Cronet fork 分支。

`kinmeic` 的 `chromium-153`、`chromium-150` 等 tag 是外部导入的源码快照，
与 `SagerNet/naiveproxy` 和 `klzgrad/naiveproxy` 没有共同祖先。`SagerNet`
与 `klzgrad` 之间有共同祖先，可以用共同基线提取 Cronet 改动；涉及
`kinmeic` 时必须按 `CHROMIUM_VERSION` 和 Chromium 提交确认版本，再按源码
内容移植。

`cronet-go` 上层仓库的 remote 另有含义：

```text
origin      个人 cronet-go fork
upstream    原始 cronet-go 仓库
```

不要把这个 `upstream` 与比较仓库中的 `<upstream>` 角色混淆。

## Local Layout

所有比较仓库和临时 worktree 都放在项目根目录内：

```text
<cronet-go-root>/
├── naiveproxy/              # 构建使用的目标源码
└── comparison/              # 临时比较目录
    ├── upstream/             # <upstream> 源码快照
    ├── cronet/               # <cronet-fork> 源码快照
    ├── target/               # <target-fork> 源码快照
    └── replay/               # 最终 patch 回放 worktree
```

`naiveproxy/` 是项目构建工具使用的实际 target 源码。`comparison/` 下的
三个目录是独立 clone，只用于比较；不要互相合并，也不要把比较目录提交
到 `cronet-go`。

## 1. Fix Source Versions

先从原始 `cronet-go` 的 `upstream/main` gitlink 获取 SagerNet/naiveproxy
的确切 commit。个人 fork 的 `origin/main` 不能作为这个版本来源：

```bash
cd <cronet-go-root>
git remote -v
git fetch upstream main
git ls-tree upstream/main <submodule-path>
```

从 `git ls-tree` 输出中记录 submodule gitlink 的 commit 为
`<cronet-commit>`。它是原始 `cronet-go` 在 `upstream/main` 中记录的
SagerNet/naiveproxy 版本。

同时确定：

```text
<matching-base>   klzgrad/naiveproxy 中与 <cronet-commit> 对应的基线
<target-tag>      target-fork 中要移植的固定 tag
```

确认 `<matching-base>` 与 `<cronet-commit>` 的 `CHROMIUM_VERSION` 和
Chromium 提交属于同一 Cronet 基线。`<target-tag>` 可以是不同的
Chromium 版本，但必须单独确认其 `CHROMIUM_VERSION` 和 Chromium 提交，
再通过编译错误完成 API 适配。不要用分支最新提交代替固定版本。

## 2. Prepare Comparison Copies

在项目根目录创建三个独立源码副本：

```bash
cd <cronet-go-root>
mkdir -p comparison
git clone <upstream> comparison/upstream
git clone <cronet-fork> comparison/cronet
git clone <target-fork> comparison/target

git -C comparison/upstream checkout --detach <matching-base>

git -C comparison/cronet remote add naive-upstream <upstream>
git -C comparison/cronet fetch naive-upstream <matching-base>
git -C comparison/cronet update-ref refs/cronet-base FETCH_HEAD
git -C comparison/cronet fetch origin <cronet-commit>
git -C comparison/cronet checkout --detach <cronet-commit>

git -C comparison/target checkout --detach <target-tag>
```

确认实际版本：

```bash
git -C comparison/upstream rev-parse HEAD
git -C comparison/cronet rev-parse HEAD
git -C comparison/cronet rev-parse refs/cronet-base
git -C comparison/target rev-parse HEAD
git -C comparison/cronet merge-base HEAD refs/cronet-base
```

最后一条只用于确认 SagerNet 与 klzgrad 的共同基线，不用于判断
`comparison/target`。target 是外部导入源码，不能要求它具有共同祖先。

## 3. Compare Source Trees

### Target Against Upstream

target 与官方源码没有共同历史时，使用源码内容比较：

```bash
git diff --no-index --stat comparison/upstream/src comparison/target/src \
  || test $? -eq 1
git diff --no-index --binary comparison/upstream/src comparison/target/src \
  > comparison/target-vs-upstream.patch || test $? -eq 1
```

这份结果只用于分析 target 相对官方源码的变化。`git diff --no-index`
发现差异时返回 1，返回其他非零值才表示命令失败。该 patch 的路径包含
比较目录，不能直接应用到 target。

### Extract Cronet Changes

SagerNet 与 klzgrad 有共同基线，从共同基线提取 Cronet 候选 patch：

```bash
git -C comparison/cronet diff --stat \
  refs/cronet-base...<cronet-commit> -- src
git -C comparison/cronet diff --binary \
  refs/cronet-base...<cronet-commit> -- src \
  > comparison/cronet.patch
```

`cronet.patch` 只是候选 patch。它可能包含针对旧 Chromium API 的改动，
也可能包含与 Cronet 无关的 hunk，不能把它视为已经适配 target 的最终 patch。

## 4. Select Target Source

`cronet-go/naiveproxy/` 必须是最终选择的 target 源码，并固定在
`<target-tag>`：

```bash
cd <cronet-go-root>
git -C naiveproxy rev-parse --is-inside-work-tree
git -C naiveproxy rev-parse --show-toplevel
git -C naiveproxy fetch --tags
git -C naiveproxy checkout --detach <target-tag>
git -C naiveproxy rev-parse HEAD
```

确认 `--show-toplevel` 指向 target 源码工作树，而不是
`<cronet-go-root>` 本身；如果 `naiveproxy/` 尚未初始化，先 clone 或初始化
正确的 target 仓库，不能让 Git 命令意外作用于父仓库。

如果使用符号链接，确保 `naiveproxy/src` 指向 target 源码根目录；如果使用
真实 submodule，只同步 `.gitmodules` 后再 checkout 固定 tag。不要在包含
其他未确认改动的工作树上生成最终 patch。

## 5. Port Cronet Changes

target 与 Cronet 源码没有共同历史时，`cronet.patch` 只能作为移植参考：

```text
1. 查看候选 patch 的文件和每个 hunk。
2. 只把 Cronet 新增文件和 Cronet 必需逻辑移植到 naiveproxy/。
3. 保留 target 已有的 Chromium 和 naiveproxy 更新。
4. 删除与 Cronet 无关、或引用 target 中不存在 API 的 hunk。
5. 不把 target-vs-upstream.patch 应用到 target。
```

如果某个改动能够直接应用，也必须逐个检查目标文件的函数签名、变量和类型。
补丁能够应用不等于代码具有正确语义。

可以先尝试直接应用；冲突必须逐个解决，且最终不能留下 `.rej` 文件：

```bash
git -C naiveproxy apply --reject --whitespace=nowarn \
  ../comparison/cronet.patch
```

## 6. Adapt Chromium APIs

应用 Cronet 改动后，从实际编译错误做最小适配：

```text
ClientSocketFactory 的方法参数和网络句柄。
DatagramClientSocket 新增的纯虚函数。
URLRequestContext::CreateRequest 的新增参数。
DNS 配置结构和枚举字段。
Time/TimeTicks 的时间转换 API。
SystemTrustStore 新增的纯虚函数。
```

适配规则：

```text
优先复用目标 Chromium 已有的 adapter、emulator 或默认实现。
只修改 Cronet 集成所需的文件。
不增加面向多个 Chromium 版本的兼容层。
不修改与 Cronet 无关的 target 逻辑。
```

## 7. Build And Test

构建工具从 `cronet-go` 根目录的 `naiveproxy/` 读取源码：

```bash
cd <cronet-go-root>
go run ./cmd/build-naive --target=<target> build
go run ./cmd/build-naive --target=<target> package --local
go run ./cmd/build-naive --target=<target> package
```

构建成功后执行测试，不能只验证库能否编译。非 Windows 平台按照项目已有
的 CGO 或 purego 测试方式执行：

```bash
go -C test test -v -timeout=12m
```

Windows 默认 CGO 测试不作为门禁；当前 Windows 静态链接方式可能缺少
Cronet metrics 等符号。Windows 使用文末的 purego 测试流程。

测试前确认 `test/engine_test.go` 中的 Chromium 版本断言与
`naiveproxy/CHROMIUM_VERSION` 一致。切换 target tag 后必须同步更新该断言，
或由构建流程根据 `CHROMIUM_VERSION` 自动更新。

至少验证：

```text
目标库可以被加载。
基础 TCP 请求成功。
UDP/QUIC 路径成功（如果启用）。
自定义 dialer 成功（如果启用）。
关闭、并发和错误路径没有回归。
```

## 8. Generate Final Patch

编译和测试通过后，检查 `naiveproxy/` 只包含 target 基线加 Cronet 改动：

```bash
git -C naiveproxy add src
git -C naiveproxy diff --cached --name-status <target-tag> -- src
```

`git diff` 默认不包含未跟踪文件。临时暂存 `src/` 后，新增文件才能进入
最终 patch。暂存只用于生成和检查，完成后撤销暂存，不要提交 target 源码：

```bash
git -C naiveproxy diff --cached --binary <target-tag> -- src \
  > <cronet-go-root>/patches/naiveproxy-cronet.patch
git -C naiveproxy reset
```

`git diff --check` 只作为代码审查辅助，不要为了消除提示而改写上游原样
导入的证书、测试数据、模板或其他 fixture；最终 patch 应保持这些文件的
原始字节。若需要检查空白，只检查本次新增或适配的代码文件。

最终 patch 是 `<target-tag>` 的增量，只能应用到同一个 target 基线或确认
兼容的源码版本。它不是跨 Chromium 版本通用的 Cronet patch。

## 9. Replay Final Patch

在全新的 target worktree 中回放最终 patch：

```bash
git -C comparison/target worktree add --detach \
  <cronet-go-root>/comparison/replay <target-tag>
git -C <cronet-go-root>/comparison/replay apply --check \
  <cronet-go-root>/patches/naiveproxy-cronet.patch
git -C <cronet-go-root>/comparison/replay apply \
  <cronet-go-root>/patches/naiveproxy-cronet.patch
```

回放成功后再次检查变更文件，并确认它与生成最终 patch 的 target 工作树一致。
只有回放和构建验证都通过，才提交 `patches/naiveproxy-cronet.patch`。

## 10. Cleanup

完成比较、构建和验证后，删除临时 worktree 和 clone，不要删除项目的
`naiveproxy/`：

```bash
git -C <cronet-go-root>/comparison/target worktree remove --force \
  <cronet-go-root>/comparison/replay
rm -rf <cronet-go-root>/comparison
```

如果还需要保留分析 patch 或比较结果，先复制到持久位置，再删除
`comparison/`。

## Windows Purego Test

Windows purego 测试需要将动态库放在测试二进制旁边。测试二进制固定使用
`cronet_windows.test.exe`，避免 Windows 防火墙重复识别随机文件名：

```bash
cd <test-directory>
go test -tags with_purego -c -o cronet_windows.test.exe .
cp <packaged-library> libcronet.dll
./cronet_windows.test.exe -test.count=1
rm -f cronet_windows.test.exe libcronet.dll
```

其他平台按照项目已有的 CGO 或 purego 测试方式执行。
