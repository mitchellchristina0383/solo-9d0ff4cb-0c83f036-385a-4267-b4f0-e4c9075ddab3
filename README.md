# Linux 崩溃栈还原服务

值班员提交崩溃栈各帧的 **ELF Build ID** 与**扣除装载偏移后的地址**，服务凭报告号返回
函数名与源码行；CI 可整批补传带 Build ID 与 DWARF 调试信息的 x86-64 ELF。
跨实例值班移交时，对端可通过 `/handoffs` 把来源实例、原报告号、原始帧与随单 ELF
一次性登记，本地号与符号绑定原子落库，重送按来源 + 原报告号幂等处理。

## 设计要点

| 需求 | 实现 |
| --- | --- |
| Build ID 从文件读取 | pyelftools 解析 `SHT_NOTE` 中的 `NT_GNU_BUILD_ID`，不信任文件名 |
| 整批退回 | 先做纯内存校验（非 ELF / 非 x86-64 / 缺 Build ID / 缺 `.debug_info`），再核对同批与已发布内容；任一不合格返回 422，无任何落盘或数据库变更 |
| 同号内容冲突 | Build ID → sha256 唯一映射，哈希不同即退回，已发布内容不可变 |
| 相同文件重传成功 | 幂等：计入 `redundant`，版本号不前进；同批内重复文件按去重处理 |
| 查询期间可发布 | 全局符号版本号每次有效发布 +1；查询在开始时取一次版本快照，只解析 `version <= 快照版本` 的 ELF |
| 未解析帧保留原地址 | 帧原样持久化，响应中带 `status=unresolved` 与原因；补传后用同一报告号再查即可 |
| 重启后可查 | 报告/帧、Build ID 映射、版本号全部存 SQLite（WAL）；ELF 按 sha256 内容寻址落盘；启动时核对并清理悬挂映射 |
| 查栈与发布并行 | 发布仅持短写锁，查询走只读快照；ELF 解析结果按 sha256 惰性缓存且不可变，可跨线程共享 |
| 跨实例移交 | `POST /handoffs`（multipart）：来源实例 + 原报告号 + 原始帧 JSON + 随单 ELF；每个非空 Build ID 须有通过同款校验的对应文件，同单同 Build ID 内容不同整单退回（422） |
| 移交原子登记 | 报告、帧、`report_elfs` 绑定在同一 SQLite 事务提交，文件先暂存再 `rename`；失败清理暂存，不留可查报告或绑定 |
| 移交幂等/冲突 | `UNIQUE(source_instance, original_report_no)`；重送帧与 build_id→sha256 全一致返回原本地号（200，`idempotent_replay=true`），任一变化返回 409；不同来源同号各发本地号 |
| 同 Build ID 异内容隔离 | 随单 ELF 仅对本报告可见，两份报告可各持同 Build ID 的不同 ELF；解析缓存以 sha256 为键，交错查栈/重启后仍各用各的文件；普通报告继续只用 `/symbols` 已发布符号 |
| Docker Compose | 单服务 + 命名卷 `symbol-data:/data`，`/docs` 提供 Swagger 演示 |

### 目录结构

```
app/
  config.py        运行期配置（SYMBOL_DATA_DIR）
  elftools_ext.py  ELF 校验 + DWARF 符号化（函数/源码行，兼容 DWARF v4/v5、PIC）
  storage.py       SQLite 持久化、原子批量发布/移交、版本快照、重启恢复
  main.py          FastAPI 路由与模型
scripts/
  build_fixtures.sh  构造固定 Build ID 的测试 ELF（含同 Build ID 异内容移交固件）
  ci_upload.py       CI 批量上传客户端
tests/             pytest 自测（含真实 uvicorn 并发交错测试）
```

## 启动

```bash
docker compose up --build
# 文档与演示： http://localhost:8000/docs
# 健康检查：    http://localhost:8000/health
```

本地无 Docker 时：

```bash
pip install -r requirements.txt
SYMBOL_DATA_DIR=./data uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/reports` | 提交崩溃帧（`build_id` 可空、`address` 支持 0x 十六进制或十进制），返回报告号与首次解析结果 |
| GET  | `/reports/{id}` | 凭报告号查询；每次查询绑定开始时的符号版本快照；移交报告附 `handoff` 元数据 |
| GET  | `/reports/{id}/raw` | 查看原始帧（地址原样保留） |
| POST | `/handoffs` | 跨实例移交（multipart）：`source_instance`、`original_report_no`、`frames`(JSON 字符串)、随单 ELF `files`；首送 201，一致重送 200，变化重送 409，校验失败 422 |
| POST | `/symbols/batch` | multipart 整批上传 ELF；整批不合格返回 422 及逐文件原因 |
| GET  | `/symbols` | 当前符号版本与已发布 Build ID 列表 |
| GET  | `/health` | 健康检查 |

未解析原因：`frame_missing_build_id` / `build_id_not_published_at_snapshot` /
`address_not_found_in_elf` / `invalid_address` /
`bound_symbol_unavailable`（移交绑定的内容文件在启动核对时缺失）。

### 示例

```bash
# 1) 值班员提交
curl -X POST localhost:8000/reports -H 'Content-Type: application/json' \
  -d '{"frames":[{"build_id":"aaaa…aaaa","address":"0x401140"}]}'

# 2) CI 整批补传
python scripts/ci_upload.py http://localhost:8000 ./build-artifacts/

# 3) 用原报告号再查
curl localhost:8000/reports/1
```

### 跨实例移交示例

`/docs`（Swagger UI）的 `POST /handoffs` 可直接填表演示；命令行等价写法：

```bash
# 1) 对端值班员移交：来源实例 site-A、原报告号 ORIG-77、原始帧 + 随单 ELF
curl -X POST localhost:8000/handoffs \
  -F 'source_instance=site-A' \
  -F 'original_report_no=ORIG-77' \
  -F 'frames=[{"build_id":"dddd…dddd","address":"0x401136"}]' \
  -F 'files=@./handoff-dddd-v1.elf'
# -> 201，返回本地 report_id 与首次解析结果（含 handoff.bound_build_ids）

# 2) 同来源同原报告号、帧与文件完全一致地重送：返回同一本地号
curl -X POST localhost:8000/handoffs \
  -F 'source_instance=site-A' -F 'original_report_no=ORIG-77' \
  -F 'frames=[{"build_id":"dddd…dddd","address":"0x401136"}]' \
  -F 'files=@./handoff-dddd-v1.elf'
# -> 200，idempotent_replay=true，report_id 与首送相同

# 3) 帧或任一 Build ID 对应文件内容变化：409 拒收，原报告与绑定不变
# 4) 另一来源 site-B 使用相同原报告号：独立 201，分配另一个本地号；
#    两份报告可各带同 Build ID 的不同 ELF，GET /reports/{id} 各解析各的文件
```

移交报告的响应在普通报告结构上额外带 `handoff`（来源、原号、绑定 Build ID 列表）；
登记响应还带 `source_instance`、`original_report_no` 与 `idempotent_replay`。

## 自测

```bash
bash scripts/build_fixtures.sh tests/fixtures/built   # 构造测试 ELF（需要 gcc）
pip install -r requirements-dev.txt
pytest -q
```

固件包含：固定 Build ID 的可执行文件与共享库、DWARF v4/v5 各一份、同 Build ID 冲突文件、
同 Build ID 异内容的移交专用 ELF（v1/v2）、无 Build ID 文件、strip 调试信息文件、非 ELF 文件。
移交相关用例见 `tests/test_handoff.py`（含真实 uvicorn 下的异内容交错查栈与重送测试）。

## 余项 / 已知边界

- 本机未安装 Docker，Compose 文件仅做 YAML 静态校验；容器路径已在同等 uvicorn 进程下端到端验证。
- 仅接受 `EM_X86_64`；其它架构在入库校验阶段明确退回。
- 符号化依赖 DWARF（`.debug_info`/`.debug_line`）；无调试信息的 ELF 不允许入库（发布与移交同款校验）。
- 移交单要求随单文件 Build ID 集合与帧引用集合精确一致：缺文件或带未引用文件都整单退回。
- 未做上传鉴权与文件大小配额，按内网服务假设；如需暴露公网应在网关层补齐。
- 当前为单实例 + 本地卷部署；多实例横向扩展需把数据层换成共享存储/数据库。
