"""持久化与发布控制。

- ELF 按 sha256 内容寻址存放（已发布符号与移交随单 ELF 共用内容目录，
  同字节文件只落盘一份），Build ID -> 内容哈希映射写入 SQLite；
- 每次整批发布把全局版本号 +1，查询只绑定解析开始时的版本快照；
- 发布全程持写锁并在同一事务内完成，任何一文件不合格则整批退回、不落盘；
- 移交单（handoff）的报告、帧与 report_elfs 绑定单事务原子登记，失败不留痕；
  绑定仅对本报告可见，不同报告可各持同 Build ID 的不同内容 ELF；
- 符号解析缓存按 sha256 键控，同 Build ID 异内容文件不会串缓存；
- 重启后从 SQLite 恢复映射并核对磁盘文件，报告/绑定同样持久化，可继续查询。
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from dataclasses import dataclass
from typing import Optional

from .config import settings
from .elftools_ext import ELFValidationError, FrameSymbol, Symbolizer, inspect_blob


@dataclass(frozen=True)
class StoredELF:
    build_id: str
    sha256: str
    path: str
    version: int  # 首次发布时的版本（+1 后的值）


class BatchRejected(Exception):
    """整批退回，message 为面向调用方的逐文件原因列表字符串。"""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class HandoffRejected(Exception):
    """移交单校验未通过（文件不合格、Build ID 覆盖不全等），整单不收。"""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class HandoffConflict(Exception):
    """同来源同原报告号重送，但帧或 Build ID 对应文件内容与首次移交不一致。"""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _normalize_build_id(build_id: Optional[str]) -> Optional[str]:
    """Build ID 统一去空白、转小写；空串视为缺失。"""
    if build_id is None:
        return None
    bid = build_id.strip().lower()
    return bid or None


class Store:
    def __init__(self, data_dir: Optional[str] = None) -> None:
        # 动态读取环境变量，避免 config 在导入时冻结路径
        self.data_dir = data_dir or os.environ.get("SYMBOL_DATA_DIR", settings.data_dir)
        self.elf_dir = os.path.join(self.data_dir, settings.elf_dir_name)
        self.db_path = os.path.join(self.data_dir, settings.db_name)
        os.makedirs(self.elf_dir, exist_ok=True)
        # 粗粒度锁：发布互斥；查询用快照版本号，不阻塞发布
        self._lock = threading.RLock()
        self._symbolizer = Symbolizer()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL");
        self._conn.execute("PRAGMA foreign_keys=ON");
        self._init_schema()
        self._reconcile_disk()

    # ------------------------------------------------------------------
    # schema 与启动恢复
    # ------------------------------------------------------------------
    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS elfs (
                    build_id TEXT PRIMARY KEY,
                    sha256   TEXT NOT NULL,
                    path     TEXT NOT NULL,
                    version  INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                );
                CREATE TABLE IF NOT EXISTS frames (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER NOT NULL REFERENCES reports(id),
                    position  INTEGER NOT NULL,
                    build_id  TEXT,
                    address   TEXT NOT NULL,
                    UNIQUE(report_id, position)
                );
                CREATE TABLE IF NOT EXISTS handoffs (
                    report_id           INTEGER PRIMARY KEY REFERENCES reports(id),
                    source_instance     TEXT NOT NULL,
                    original_report_no  TEXT NOT NULL,
                    snapshot_symbol_version INTEGER NOT NULL,
                    UNIQUE(source_instance, original_report_no)
                );
                CREATE TABLE IF NOT EXISTS report_elfs (
                    report_id INTEGER NOT NULL REFERENCES reports(id),
                    build_id  TEXT NOT NULL,
                    sha256    TEXT NOT NULL,
                    path      TEXT NOT NULL,
                    PRIMARY KEY (report_id, build_id)
                );
                CREATE INDEX IF NOT EXISTS idx_report_elfs_sha
                    ON report_elfs(sha256);
                """
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('symbol_version', 0)"
            )

    def _reconcile_disk(self) -> None:
        """重启后核对：磁盘缺失的内容文件删除其映射，保证不悬挂。

        已发布符号（elfs）与移交单绑定（report_elfs）共用内容寻址目录，
        两类映射都要核对；绑定缺失的帧在查询时明确报
        bound_symbol_unavailable 而非静默退回未发布状态。
        """
        with self._lock, self._conn:
            for table in ("elfs", "report_elfs"):
                rows = self._conn.execute(
                    f"SELECT DISTINCT sha256, path FROM {table}"
                ).fetchall()
                for row in rows:
                    if not os.path.isfile(row["path"]):
                        self._conn.execute(
                            f"DELETE FROM {table} WHERE sha256=?", (row["sha256"],)
                        )
                        self._symbolizer.evict(row["sha256"])

    @property
    def symbol_version(self) -> int:
        return int(self._conn.execute("SELECT value FROM meta WHERE key='symbol_version'").fetchone()["value"])

    # ------------------------------------------------------------------
    # 批量发布
    # ------------------------------------------------------------------
    def publish_batch(self, files: list[tuple[str, bytes]]) -> dict:
        """原子发布一批 ELF。

        files 为 (原始文件名, 文件字节)。任一文件不合格或同 Build ID 内容冲突，
        抛 BatchRejected，整批退回（无任何落盘/数据库变更）。
        内容完全相同的重复文件（含同批内重复）按成功处理（幂等）。
        """
        if not files:
            raise BatchRejected(["批次为空：未收到任何文件"])

        errors: list[str] = []
        # 第一阶段：纯内存校验 + 同批去重，不落盘
        unique: dict[str, tuple[str, bytes, str]] = {}  # build_id -> (filename, blob, sha256)
        in_batch_duplicates = 0
        for filename, blob in files:
            try:
                build_id, _ = inspect_blob(blob)
            except ELFValidationError as exc:
                errors.append(f"{filename}: {exc}")
                continue
            digest = hashlib.sha256(blob).hexdigest()
            prev = unique.get(build_id)
            if prev is not None:
                if prev[2] != digest:
                    errors.append(
                        f"{filename}: Build ID {build_id} 与同批文件 {prev[0]} 内容不同"
                    )
                else:
                    in_batch_duplicates += 1  # 同批内完全相同的重复文件
                continue
            unique[build_id] = (filename, blob, digest)

        with self._lock:
            # 第二阶段：与已发布内容核对冲突
            existing = {
                r["build_id"]: r
                for r in self._conn.execute("SELECT build_id, sha256 FROM elfs").fetchall()
            }
            for build_id, (filename, _blob, digest) in unique.items():
                row = existing.get(build_id)
                if row is not None and row["sha256"] != digest:
                    errors.append(
                        f"{filename}: Build ID {build_id} 已发布且文件内容不同"
                    )

            if errors:
                raise BatchRejected(sorted(set(errors)))

            # 第三阶段：先把所有新内容文件暂存落盘（rename 原子可见），
            # 再用单个数据库事务写入映射与版本号；任一步失败则清理暂存并整体回滚。
            new_entries: list[tuple[str, str, str]] = []  # (build_id, sha256, path)
            redundant = in_batch_duplicates
            staged_paths: list[str] = []
            for build_id, (filename, blob, digest) in unique.items():
                if build_id in existing:
                    redundant += 1
                    continue
                final_path = os.path.join(self.elf_dir, f"{digest}.elf")
                if not os.path.exists(final_path):
                    tmp_path = os.path.join(
                        self.elf_dir, f".tmp-{os.getpid()}-{threading.get_ident()}-{digest}"
                    )
                    with open(tmp_path, "wb") as fh:
                        fh.write(blob)
                    os.replace(tmp_path, final_path)
                    staged_paths.append(final_path)
                new_entries.append((build_id, digest, final_path))

            if new_entries:
                next_version = self.symbol_version + 1
                try:
                    with self._conn:  # 单事务：映射与版本号一起提交
                        self._conn.executemany(
                            "INSERT INTO elfs(build_id, sha256, path, version)"
                            " VALUES(?,?,?,?)",
                            [(bid, digest, path, next_version) for bid, digest, path in new_entries],
                        )
                        self._conn.execute(
                            "UPDATE meta SET value=? WHERE key='symbol_version'",
                            (next_version,),
                        )
                except BaseException:
                    for path in staged_paths:
                        try:
                            os.remove(path)
                        except OSError:
                            pass
                    raise

        return {
            "accepted": len(files),
            "new_build_ids": sorted(bid for bid, _d, _p in new_entries),
            "redundant": redundant,
            "symbol_version": self.symbol_version,
        }

    # ------------------------------------------------------------------
    # 报告
    # ------------------------------------------------------------------
    def create_report(self, frames: list[dict]) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute("INSERT INTO reports DEFAULT VALUES")
            report_id = cur.lastrowid
            for pos, frame in enumerate(frames):
                self._conn.execute(
                    "INSERT INTO frames(report_id, position, build_id, address)"
                    " VALUES(?,?,?,?)",
                    (report_id, pos, frame.get("build_id"), str(frame["address"])),
                )
            return report_id

    def get_report_raw(self, report_id: int) -> Optional[dict]:
        report = self._conn.execute(
            "SELECT id, created_at FROM reports WHERE id=?", (report_id,)
        ).fetchone()
        if report is None:
            return None
        frames = self._conn.execute(
            "SELECT position, build_id, address FROM frames"
            " WHERE report_id=? ORDER BY position",
            (report_id,),
        ).fetchall()
        return {
            "report_id": report["id"],
            "created_at": report["created_at"],
            "frames": [
                {"position": f["position"], "build_id": f["build_id"], "address": f["address"]}
                for f in frames
            ],
        }

    # ------------------------------------------------------------------
    # 移交（handoff）：来源实例 + 原报告号 + 原始帧 + 随单 ELF
    # ------------------------------------------------------------------
    def intake_handoff(
        self,
        source_instance: str,
        original_report_no: str,
        frames: list[dict],
        files: list[tuple[str, bytes]],
    ) -> dict:
        """登记一份跨实例移交的崩溃报告及其随单 ELF。

        校验全部通过前不落盘、不写库；通过后报告、帧、Build ID 绑定在同一
        事务内原子登记。同来源同原报告号重送时做幂等判定：
        帧与 build_id->sha256 完全一致返回原本地号，否则抛 HandoffConflict。
        """
        source_instance = (source_instance or "").strip()
        original_report_no = (original_report_no or "").strip()
        if not source_instance:
            raise HandoffRejected(["source_instance 不能为空"])
        if not original_report_no:
            raise HandoffRejected(["original_report_no 不能为空"])
        if not frames:
            raise HandoffRejected(["原始帧不能为空"])

        # 规范化帧；地址按原始字符串持久化，Build ID 统一小写
        norm_frames: list[dict] = []
        required_build_ids: set[str] = set()
        for pos, frame in enumerate(frames):
            address = frame.get("address")
            if address is None or str(address).strip() == "":
                raise HandoffRejected([f"第 {pos} 帧缺少 address"])
            bid = _normalize_build_id(frame.get("build_id"))
            norm_frames.append({"build_id": bid, "address": str(address)})
            if bid:
                required_build_ids.add(bid)

        # 第一阶段：纯内存校验每个文件（沿用发布同款校验），同单内同 Build ID
        # 内容不同即拒收；同内容重复文件按去重处理。
        errors: list[str] = []
        unique: dict[str, tuple[str, bytes, str]] = {}  # build_id -> (filename, blob, sha256)
        for filename, blob in files:
            if not blob:
                errors.append(f"{filename}: 文件为空")
                continue
            try:
                build_id, _ = inspect_blob(blob)
            except ELFValidationError as exc:
                errors.append(f"{filename}: {exc}")
                continue
            digest = hashlib.sha256(blob).hexdigest()
            prev = unique.get(build_id)
            if prev is not None:
                if prev[2] != digest:
                    errors.append(
                        f"{filename}: Build ID {build_id} 与同单文件 {prev[0]} 内容不同"
                    )
                # 同内容重复文件直接去重，保留首次出现的那份
                continue
            unique[build_id] = (filename, blob, digest)

        # 覆盖性核对：帧里每个非空 Build ID 都须有一个通过校验的对应文件，
        # 随单文件也不允许带帧未引用的 Build ID（整单语义自洽）。
        supplied = set(unique.keys())
        for bid in sorted(required_build_ids - supplied):
            errors.append(f"帧引用的 Build ID {bid} 缺少随单 ELF 文件")
        for bid in sorted(supplied - required_build_ids):
            errors.append(
                f"随单文件 Build ID {bid} 未被任何帧引用，移交单不接受多余文件"
            )

        with self._lock:
            # 幂等判定：同来源同原报告号是否已登记
            existing = self._conn.execute(
                "SELECT h.report_id AS report_id, h.snapshot_symbol_version AS snap"
                " FROM handoffs h WHERE source_instance=? AND original_report_no=?",
                (source_instance, original_report_no),
            ).fetchone()
            if existing is not None:
                self._check_handoff_replay(
                    existing["report_id"], norm_frames, unique, errors
                )
                if errors:
                    raise HandoffConflict(sorted(set(errors)))
                # 完全一致：幂等返回原本地号，不产生任何写入
                result = self.resolve_report(existing["report_id"])
                result["idempotent_replay"] = True
                result["source_instance"] = source_instance
                result["original_report_no"] = original_report_no
                return result

            if errors:
                raise HandoffRejected(sorted(set(errors)))

            # 第二阶段：内容文件暂存落盘（os.replace 原子可见），随后单事务
            # 写报告/帧/移交信息/绑定；事务失败则清理本次暂存文件。
            snapshot_version = self.symbol_version
            staged: list[tuple[str, str, str]] = []  # (build_id, sha256, path)
            staged_paths: list[str] = []
            for build_id, (_filename, blob, digest) in unique.items():
                final_path = os.path.join(self.elf_dir, f"{digest}.elf")
                if not os.path.exists(final_path):
                    tmp_path = os.path.join(
                        self.elf_dir,
                        f".tmp-handoff-{os.getpid()}-{threading.get_ident()}-{digest}",
                    )
                    with open(tmp_path, "wb") as fh:
                        fh.write(blob)
                    os.replace(tmp_path, final_path)
                    staged_paths.append(final_path)
                staged.append((build_id, digest, final_path))

            try:
                with self._conn:  # 报告、帧、移交元数据、绑定单事务提交
                    cur = self._conn.execute("INSERT INTO reports DEFAULT VALUES")
                    report_id = cur.lastrowid
                    self._conn.executemany(
                        "INSERT INTO frames(report_id, position, build_id, address)"
                        " VALUES(?,?,?,?)",
                        [
                            (report_id, pos, f["build_id"], f["address"])
                            for pos, f in enumerate(norm_frames)
                        ],
                    )
                    self._conn.execute(
                        "INSERT INTO handoffs(report_id, source_instance,"
                        " original_report_no, snapshot_symbol_version) VALUES(?,?,?,?)",
                        (report_id, source_instance, original_report_no, snapshot_version),
                    )
                    self._conn.executemany(
                        "INSERT INTO report_elfs(report_id, build_id, sha256, path)"
                        " VALUES(?,?,?,?)",
                        [(report_id, bid, digest, path) for bid, digest, path in staged],
                    )
            except BaseException:
                for path in staged_paths:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                raise

        result = self.resolve_report(report_id)
        result["idempotent_replay"] = False
        result["source_instance"] = source_instance
        result["original_report_no"] = original_report_no
        return result

    def _check_handoff_replay(
        self,
        report_id: int,
        norm_frames: list[dict],
        unique: dict[str, tuple[str, bytes, str]],
        errors: list[str],
    ) -> None:
        """重送一致性核对：帧序列与 build_id->sha256 映射都必须与首送相同。"""
        old_frames = self._conn.execute(
            "SELECT position, build_id, address FROM frames"
            " WHERE report_id=? ORDER BY position",
            (report_id,),
        ).fetchall()
        if len(old_frames) != len(norm_frames):
            errors.append(
                f"重送帧数量 {len(norm_frames)} 与原单 {len(old_frames)} 不一致"
            )
        else:
            for pos, (old, new) in enumerate(zip(old_frames, norm_frames)):
                if old["build_id"] != new["build_id"] or old["address"] != new["address"]:
                    errors.append(
                        f"第 {pos} 帧与原单不一致："
                        f"原 (build_id={old['build_id']}, address={old['address']})，"
                        f"新 (build_id={new['build_id']}, address={new['address']})"
                    )
        old_bindings = {
            r["build_id"]: r["sha256"]
            for r in self._conn.execute(
                "SELECT build_id, sha256 FROM report_elfs WHERE report_id=?",
                (report_id,),
            ).fetchall()
        }
        new_bindings = {bid: item[2] for bid, item in unique.items()}
        if set(old_bindings) != set(new_bindings):
            errors.append(
                f"重送 Build ID 集合与原单不一致：原 {sorted(old_bindings)}，"
                f"新 {sorted(new_bindings)}"
            )
        for bid, digest in new_bindings.items():
            if bid in old_bindings and old_bindings[bid] != digest:
                errors.append(
                    f"Build ID {bid} 对应文件内容与原单不同（sha256 不一致）"
                )

    def _handoff_meta(self, report_id: int) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT report_id, source_instance, original_report_no,"
            " snapshot_symbol_version FROM handoffs WHERE report_id=?",
            (report_id,),
        ).fetchone()

    def _handoff_bindings(self, report_id: int) -> dict[str, StoredELF]:
        rows = self._conn.execute(
            "SELECT build_id, sha256, path FROM report_elfs WHERE report_id=?",
            (report_id,),
        ).fetchall()
        return {
            r["build_id"]: StoredELF(
                r["build_id"], r["sha256"], r["path"], 0
            )
            for r in rows
        }

    # ------------------------------------------------------------------
    # 快照符号化
    # ------------------------------------------------------------------
    def snapshot_paths(self, version: int) -> dict[str, StoredELF]:
        """取 <= version 的已发布 ELF 映射（查询开始时调用一次）。"""
        rows = self._conn.execute(
            "SELECT build_id, sha256, path, version FROM elfs WHERE version <= ?",
            (version,),
        ).fetchall()
        return {
            r["build_id"]: StoredELF(r["build_id"], r["sha256"], r["path"], r["version"])
            for r in rows
        }

    def resolve_report(self, report_id: int, snapshot_version: Optional[int] = None) -> Optional[dict]:
        raw = self.get_report_raw(report_id)
        if raw is None:
            return None
        handoff = self._handoff_meta(report_id)
        if handoff is not None:
            # 移交报告只使用随单绑定的 ELF，与已发布符号池完全隔离；
            # 快照版本固定为移交登记时刻的全局符号版本（普通符号不参与解析，
            # 仅用于响应展示与跨重启一致性）。
            version = handoff["snapshot_symbol_version"]
            available = self._handoff_bindings(report_id)
            missing_reason = "bound_symbol_unavailable"
        else:
            version = self.symbol_version if snapshot_version is None else snapshot_version
            available = self.snapshot_paths(version)
            missing_reason = "build_id_not_published_at_snapshot"
        resolved_frames = []
        for frame in raw["frames"]:
            item = {
                "position": frame["position"],
                "build_id": frame["build_id"],
                "address": frame["address"],
                "status": "unresolved",
                "reason": None,
                "function": None,
                "source_file": None,
                "source_line": None,
            }
            build_id = frame["build_id"]
            if not build_id:
                item["reason"] = "frame_missing_build_id"
            else:
                stored = available.get(build_id.lower())
                if stored is None:
                    item["reason"] = missing_reason
                else:
                    try:
                        address = int(frame["address"], 0)
                    except ValueError:
                        item["reason"] = "invalid_address"
                        resolved_frames.append(item)
                        continue
                    # 缓存键用内容哈希：同 Build ID 不同内容的两份 ELF 各自缓存
                    sym: FrameSymbol = self._symbolizer.symbolize(
                        stored.path, stored.sha256, address
                    )
                    item["function"] = sym.function
                    item["source_file"] = sym.file
                    item["source_line"] = sym.line
                    item["status"] = "resolved" if sym.resolved() else "unresolved"
                    if not sym.resolved():
                        item["reason"] = "address_not_found_in_elf"
            resolved_frames.append(item)
        resolved_count = sum(1 for f in resolved_frames if f["status"] == "resolved")
        result = {
            "report_id": report_id,
            "created_at": raw["created_at"],
            "snapshot_symbol_version": version,
            "current_symbol_version": self.symbol_version,
            "frame_count": len(resolved_frames),
            "resolved_count": resolved_count,
            "frames": resolved_frames,
        }
        if handoff is not None:
            result["handoff"] = {
                "source_instance": handoff["source_instance"],
                "original_report_no": handoff["original_report_no"],
                "bound_build_ids": sorted(available.keys()),
            }
        return result

    def list_build_ids(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT build_id, sha256, version FROM elfs ORDER BY build_id"
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
