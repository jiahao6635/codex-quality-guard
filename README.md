# Codex Quality Guard

`codex-proxy-rs` 独立插件：对指定 OpenAI 账号执行 ModelTrace 行为探针，连续异常后移出健康组，冷却后复测通过再放回。插件 ID：`jiahao6635.quality-guard`。

**这是行为一致性检测。ModelTrace 分数不是后端模型身份证，单独探针也不能确认此前哪一次业务请求被替换了模型。** 本版本没有部署到生产，未发真实推理；本地验证范围见 [验证说明](docs/validation.md)。

## 分组方式

| 资源 | 成员 / 用途 |
| --- | --- |
| 插件自有探测组 | 配置中纳管、原生启用且属于 OpenAI 的账号；包含质量冷却账号 |
| 插件自有健康组 | 通过准入的账号；连续异常后移出，恢复通过后加入 |
| 插件自有探针 Key | 只绑定探测组，供插件固定账号推理；不得提供给业务客户端 |
| 插件自有业务 Key | 只绑定健康组，供业务使用 |

插件由宿主自动维护入口创建这些资源并同步成员。它不改账号原生 `enabled`，原生禁用账号不会被探针重新启用。停止插件或定时器也不会自动恢复已隔离账号。

一个实例检测一个 `model`，健康组按账号控制访问。该模型通过检测不代表同账号的其他模型也已验证。业务 Key 若还绑定其他组，就可能绕过健康组；所有实际业务入口都必须只访问健康组。

从 0.1.0 升级到 0.1.1 时，先删除旧配置中的 `provider` 字段；已有探测状态可直接读取，冷却与恢复进度保留。

## 安装与首次启用

### 1. 准备兼容宿主与插件包

- 宿主：`codex-proxy-rs >=3.17.0, <4.0.0`，支持当前进程插件合同。
- SDK 固定为提交 `e06ca56f935774505aed0bd0ec3a2bc475e5e502`；宿主、SDK、打包 CLI 须保持合同兼容。
- 本地构建需要 Rust **1.97**、Node.js **22**、Python 3、Bash 和目标平台编译工具。

在目标平台构建，例如 Linux x86_64：

```sh
cargo test --manifest-path backend/Cargo.toml --locked
node scripts/verify-scorer.mjs
bash scripts/package.sh x86_64-unknown-linux-gnu
ls dist/*.tar.gz dist/*.sha256
```

打包脚本安装与 SDK 同提交的 `cpr-plugin` 到项目 `.cache/`，生成宿主可安装的包和摘要。其他支持目标为 `aarch64-unknown-linux-gnu`、`aarch64-apple-darwin`；跨平台构建需自行准备目标工具链和链接器。

也可在仓库 **Actions → CI** 成功运行后下载 `codex-quality-guard-linux-x86_64` artifact，解压后取得其中的 `tar.gz` 和 `sha256`。这是 CI 制品，不等同于已发布的 GitHub Release。

### 2. 安装并让宿主准备资源

在宿主“插件管理”上传 `tar.gz`，检查平台、摘要和访问域后按宿主安装流程接受制品。插件使用：

- `models`：通过宿主模型链发起定向探针。
- `data`：读取账号基础事实及 Key 分组范围，不读取账号凭据。
- `groups`：维护本实例自有探测组和健康组。
- `keys`：创建绑定自有分组的 Key 并读取预算；插件不读取密钥明文。

保持插件配置的 **`enabled: false`**。宿主实例需处于启用状态，才能运行维护和命令；这是两个不同开关。维护会创建分组与 Key，但此时 `tick` 不发推理，且不开始账号成员同步。

取得插件配置的 **实例 UUID**，在与网关相同的工作目录、系统身份及环境中执行：

```sh
export CPR_BIN=/opt/codex-proxy-rs/codex-proxy-rs
export QUALITY_GUARD_INSTANCE_ID=替换为已安装配置的实例UUID
cd /opt/codex-proxy-rs
"$CPR_BIN" plugin "$QUALITY_GUARD_INSTANCE_ID" status
```

这里调用的是**宿主二进制**，不是包内插件可执行文件。实例 UUID 也不是 `jiahao6635.quality-guard`。若资源为空，检查实例是否启用、访问域、维护错误和宿主日志，等待维护完成；`status` 本身不会创建资源。

### 3. 配置账号与业务访问范围

以 [config.example.json](config.example.json) 为模板，在宿主插件设置中填写：

1. `account_ids`：实际账号 ID，最多100个；插件固定使用 OpenAI。
2. `model`：实际用于质量检测的模型，默认 `gpt-6-astra`。确认此模型没有经其他插件或网关别名规则改写；指定账号不代表绕过宿主模型路由。
3. 业务客户端使用自有业务 Key，或将现有业务 Key **仅绑定到 status 返回的健康组**，并把这些现有 Key 的 ID 填入 `business_key_ids`。该列表用于范围校验，不自动修改已有 Key 的分组。
4. 检查探针 Key 的日、周美元预算。字段使用十进制字符串，如 `"5"`、`"25"`。自有 Key 创建后，插件不覆盖管理员修改过的预算，只验证它们为正数且不宽于配置值。下调配置时也要在宿主 Key 管理中同步收紧已有 Key，否则探针停止并报告预算错误。
5. 将配置 `enabled` 改为 `true` 并保存。等待维护将纳管账号加入探测组；未经过准入的账号不进入健康组。

在 `status` 中确认 `key_scopes_ok: true`、`probe_budget_ok: true`、`maintenance.ok: true`、账号范围正确。探针 Key 永不外用；插件 status 只包含资源 ID，不回显密钥。未纳入校验的其他业务 Key 仍由部署者确保不存在旁路。

### 4. 执行探针并启用定时器

```sh
"$CPR_BIN" plugin "$QUALITY_GUARD_INSTANCE_ID" tick
"$CPR_BIN" plugin "$QUALITY_GUARD_INSTANCE_ID" status
```

**`tick` 会产生真实推理消耗**，每次最多完成一个到期账号的一道题。它只写探测证据，分组变更由宿主自动维护对账执行，二者不是同一事务。首次准入需要完整一轮三份正常样本；单次 `tick` 成功不等于账号已经可用。

按 [systemd 部署说明](deploy/README.md) 配置原生定时器，默认在上次执行结束后30秒再触发。模板面向直接运行宿主二进制的部署；容器环境须使用同一容器环境适配宿主 CLI，不能在另一套数据库上运行。

## 默认判定与恢复

| 阶段 | 默认规则 |
| --- | --- |
| 单份样本 | 完整成功文本、无工具/上游错误；整数数量精确、范围1～355；不截断、不补齐、不从解释正文抽取 |
| 正常 | 第一候选等于请求模型，库内分数 ≥0.99 |
| 异常 | 第一候选不同，分数 ≥0.99，预期模型分数 ≤0.01 |
| 无法判定 | 超时、错误、格式不符、数量不符或分数不足；不计异常、不据此恢复 |
| 首次准入 | 一轮3份连续正常样本 |
| 异常隔离 | 同一替代候选连续2轮、每轮3份异常；两轮间隔至少5分钟 |
| 冷却 | 初始1小时；到期只允许恢复探测，不按时间直接放行 |
| 恢复 | 连续2轮、每轮3份正常；两轮间隔至少10分钟 |
| 恢复失败 | 异常或无法判定均保持隔离，冷却退避至2、4、最多6小时 |
| 正常巡检 | 正常一轮结束后30分钟再次到期；实际执行还受队列与预算限制 |

混合结果、候选改变、未知样本会打断相应连续证据，不能拼接成完整异常或恢复轮。阈值是保守运行策略，未经过当前部署环境独立误报校准。

### 全池保护

当曾通过准入的纳管账号数大于1，且其中 `cooling/recovering` 比例**超过** `max_quarantined_percent`（默认50）时，维护暂停继续将这些账号从健康组移出，并在 `maintenance.pool_guard` 标记异常。已经被移出的账号不会因此加回。它保留现有可用容量，也意味着部分已判异常账号可能暂留健康组，应及时检查指纹漂移或上游整体变化。

单账号池仍会正常隔离。设为100可关闭这个比例保护；此时全部账号都有可能被移出健康组。

## 消耗、状态与边界

- 每次使用新挑战，固定 `reasoning.effort=low`，默认 `max_output_tokens=4096`。不携带业务上下文或旧 turn-state。
- 默认全插件每天最多100次尝试，预留输出总额409600 tokens；按 **UTC 日期**计数。发起前预留整份上限，失败也不退款。它们是插件发起预算，上游可能忽略输出参数，不能保证真实费用硬上限；宿主 Key 预算是额外约束。
- 多账号共用串行探针与日预算。额度耗尽会形成监测空窗，`overdue_ms` 可用于观察滞后；探针通过不保证下一次业务请求仍使用相同模型。
- 修改目标模型、评分阈值或判定策略会要求重新准入；已有冷却保留恢复门槛与租约。批量修改可能暂时移空健康组，应在受控入口验证。
- 从纳管配置移除的账号会退出两组，旧状态在租约结束后清理；重新纳管须重新准入。
- 每账号只保存最近12份证据摘要：时间、挑战 ID、宿主请求 ID、分类、分数和错误码；不保存原始探针答案或生产正文。宿主自己的请求日志与留存策略独立。
- V1 无专属管理页。用 `status` CLI，或管理员在宿主实例管理入口调用插件相对路由 **`GET /status`**；不要把它当作宿主根路径 `/status`。
- `maintenance.membership=database_readback_only`、`runtime_isolation_verified=false` 明示当前只有组成员数据库读回。变更传播到调度缓存、业务 Key 真正不再选到隔离账号，需要实际网关验收；已开始的请求不会被撤回。
- 配置 `enabled=false` 暂停探针和成员同步；停用宿主实例停止维护；停止 timer 仅停止新增 tick。自有资源和现有成员保留，撤销业务访问应在宿主 Key 管理中处理。

## 开发与来源

```sh
cargo fmt --manifest-path backend/Cargo.toml --all -- --check
cargo clippy --manifest-path backend/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path backend/Cargo.toml --locked
node scripts/verify-scorer.mjs
```

ModelTrace 固定提交 `df3a0f9d3e054c0dc02d6d586686db8daf8fa7c8`，源码与数据的 MIT 许可、SHA256 和边界见 [data/modeltrace](data/modeltrace/README.md)。运行时不自动更新指纹库。独立插件不会修改宿主仓库代码。
