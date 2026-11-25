"""跨实例移交（handoff）自测。

覆盖：随单 ELF 校验与整单原子性、幂等重送（同号一致/变化拒收/异源各发本地号）、
同 Build ID 异内容文件的报告级绑定隔离（交错查栈 + 重启）、与普通发布符号池的隔离、
以及 multipart HTTP 接口。
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import httpx
import pytest
from elftools.elf.elffile import ELFFile

from app.storage import HandoffConflict, HandoffRejected, Store

FIX = Path(__file__).resolve().parent / "fixtures" / "built"
BUILD_ID_A = "a" * 40
BUILD_ID_B = "b" * 40
BUILD_ID_D = "d" * 40
BUILD_ID_E = "e" * 40


def read_fixture(name: str) -> bytes:
    return (FIX / name).read_bytes()


def func_address(elf_path: Path, func: str) -> int:
    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_SYMTAB":
                continue
            for sym in section.iter_symbols():
                if sym.name == func and sym["st_info"]["type"] == "STT_FUNC":
                    return sym["st_value"]
    raise AssertionError(f"符号 {func} 未在 {elf_path} 中找到")


def handoff_files(*names: str) -> list[tuple[str, bytes]]:
    return [(n, read_fixture(n)) for n in names]


def make_frames(build_id: str | None, address: int) -> list[dict]:
    return [{"build_id": build_id, "address": hex(address)}]


# ---------------------------------------------------------------------------
# 1. 登记与绑定解析
# ---------------------------------------------------------------------------
def test_handoff_intake_registers_report_and_resolves_with_bound_elf(store):
    addr = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    result = store.intake_handoff(
        "site-A", "ORIG-1", make_frames(BUILD_ID_D, addr),
        handoff_files("handoff-dddd-v1.elf"),
    )
    assert result["idempotent_replay"] is False
    assert result["handoff"]["source_instance"] == "site-A"
    assert result["handoff"]["original_report_no"] == "ORIG-1"
    assert result["handoff"]["bound_build_ids"] == [BUILD_ID_D]
    frame = result["frames"][0]
    assert frame["status"] == "resolved"
    assert frame["function"] == "handoff_origin_func"
    assert frame["source_file"].endswith("handoff_v1.c")

    # 原始帧可查、地址原样保留
    raw = store.get_report_raw(result["report_id"])
    assert raw["frames"][0]["address"] == hex(addr)


def test_handoff_frame_with_empty_build_id_needs_no_file(store):
    result = store.intake_handoff(
        "site-A", "ORIG-EMPTY",
        [{"build_id": None, "address": "0x1234"}],
        [],
    )
    frame = result["frames"][0]
    assert frame["status"] == "unresolved"
    assert frame["reason"] == "frame_missing_build_id"
    assert frame["address"] == "0x1234"


def test_handoff_supports_multiple_build_ids_in_one_order(store):
    addr_d = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    addr_e = func_address(FIX / "handoff-eeee.elf", "other_func")
    result = store.intake_handoff(
        "site-A", "ORIG-MULTI",
        [
            {"build_id": BUILD_ID_D, "address": hex(addr_d)},
            {"build_id": BUILD_ID_E, "address": hex(addr_e)},
        ],
        handoff_files("handoff-dddd-v1.elf", "handoff-eeee.elf"),
    )
    assert result["resolved_count"] == 2
    assert sorted(result["handoff"]["bound_build_ids"]) == [BUILD_ID_D, BUILD_ID_E]


# ---------------------------------------------------------------------------
# 2. 校验：缺文件 / 多余文件 / 坏文件 / 同单冲突，失败不留痕
# ---------------------------------------------------------------------------
def test_handoff_rejected_when_frame_build_id_has_no_file(store):
    addr = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    with pytest.raises(HandoffRejected) as exc:
        store.intake_handoff(
            "site-A", "ORIG-X", make_frames(BUILD_ID_D, addr), []
        )
    assert any("缺少随单 ELF" in e for e in exc.value.errors)
    _assert_no_handoff_trace(store)


def test_handoff_rejected_when_file_not_referenced_by_frames(store):
    addr = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    with pytest.raises(HandoffRejected) as exc:
        store.intake_handoff(
            "site-A", "ORIG-X", make_frames(BUILD_ID_D, addr),
            handoff_files("handoff-dddd-v1.elf", "handoff-eeee.elf"),
        )
    assert any("未被任何帧引用" in e for e in exc.value.errors)
    _assert_no_handoff_trace(store)


def test_handoff_rejected_when_elf_fails_original_validation(store):
    addr = 0x1000
    with pytest.raises(HandoffRejected) as exc:
        store.intake_handoff(
            "site-A", "ORIG-X", make_frames("c" * 40, addr),
            [("stripped.elf", read_fixture("stripped-cccc.elf"))],
        )
    assert any("调试信息" in e for e in exc.value.errors)
    _assert_no_handoff_trace(store)


def test_handoff_rejected_on_same_buildid_different_content_within_order(store):
    addr = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    with pytest.raises(HandoffRejected) as exc:
        store.intake_handoff(
            "site-A", "ORIG-X", make_frames(BUILD_ID_D, addr),
            handoff_files("handoff-dddd-v1.elf", "handoff-dddd-v2.elf"),
        )
    assert any("内容不同" in e for e in exc.value.errors)
    _assert_no_handoff_trace(store)


def test_handoff_rejected_when_frames_empty(store):
    with pytest.raises(HandoffRejected):
        store.intake_handoff("site-A", "ORIG-X", [], handoff_files("handoff-dddd-v1.elf"))


def _assert_no_handoff_trace(store: Store) -> None:
    """失败后不留可查报告、绑定或落盘文件。"""
    assert store._conn.execute("SELECT COUNT(*) AS n FROM reports").fetchone()["n"] == 0
    assert store._conn.execute("SELECT COUNT(*) AS n FROM handoffs").fetchone()["n"] == 0
    assert store._conn.execute("SELECT COUNT(*) AS n FROM report_elfs").fetchone()["n"] == 0
    assert store._conn.execute("SELECT COUNT(*) AS n FROM frames").fetchone()["n"] == 0
    import os

    assert [n for n in os.listdir(store.elf_dir) if not n.startswith(".")] == []


# ---------------------------------------------------------------------------
# 3. 幂等重送
# ---------------------------------------------------------------------------
def _first_handoff(store: Store, elf_name: str = "handoff-dddd-v1.elf") -> tuple[int, int]:
    addr = func_address(FIX / elf_name, "handoff_origin_func")
    result = store.intake_handoff(
        "site-A", "ORIG-7", make_frames(BUILD_ID_D, addr),
        handoff_files(elf_name),
    )
    return result["report_id"], addr


def test_identical_replay_returns_same_local_id(store):
    report_id, addr = _first_handoff(store)
    again = store.intake_handoff(
        "site-A", "ORIG-7", make_frames(BUILD_ID_D, addr),
        handoff_files("handoff-dddd-v1.elf"),
    )
    assert again["idempotent_replay"] is True
    assert again["report_id"] == report_id
    # 没有产生第二份报告/绑定
    assert store._conn.execute("SELECT COUNT(*) AS n FROM reports").fetchone()["n"] == 1
    assert store._conn.execute("SELECT COUNT(*) AS n FROM report_elfs").fetchone()["n"] == 1


def test_replay_with_changed_frame_is_conflict(store):
    report_id, addr = _first_handoff(store)
    with pytest.raises(HandoffConflict) as exc:
        store.intake_handoff(
            "site-A", "ORIG-7",
            [{"build_id": BUILD_ID_D, "address": hex(addr + 1)}],
            handoff_files("handoff-dddd-v1.elf"),
        )
    assert any("帧" in e for e in exc.value.errors)
    # 原报告仍可查且内容未变
    raw = store.get_report_raw(report_id)
    assert raw["frames"][0]["address"] == hex(addr)


def test_replay_with_changed_elf_content_is_conflict(store):
    report_id, addr = _first_handoff(store)
    with pytest.raises(HandoffConflict) as exc:
        store.intake_handoff(
            "site-A", "ORIG-7", make_frames(BUILD_ID_D, addr),
            handoff_files("handoff-dddd-v2.elf"),  # 同 Build ID，不同 sha256
        )
    assert any("sha256 不一致" in e for e in exc.value.errors)
    # 原绑定仍指向 v1 内容
    result = store.resolve_report(report_id)
    assert result["frames"][0]["source_file"].endswith("handoff_v1.c")


def test_different_sources_same_original_no_get_distinct_local_ids(store):
    _, addr = _first_handoff(store)
    other = store.intake_handoff(
        "site-B", "ORIG-7", make_frames(BUILD_ID_D, addr),
        handoff_files("handoff-dddd-v2.elf"),
    )
    first = store.intake_handoff(
        "site-A", "ORIG-7", make_frames(BUILD_ID_D, addr),
        handoff_files("handoff-dddd-v1.elf"),
    )
    assert other["idempotent_replay"] is False
    assert other["report_id"] != first["report_id"]
    assert first["idempotent_replay"] is True  # site-A 重送仍是原号


def test_replay_with_changed_build_id_set_is_conflict(store):
    report_id, addr = _first_handoff(store)
    addr_e = func_address(FIX / "handoff-eeee.elf", "other_func")
    with pytest.raises(HandoffConflict) as exc:
        store.intake_handoff(
            "site-A", "ORIG-7",
            [
                {"build_id": BUILD_ID_D, "address": hex(addr)},
                {"build_id": BUILD_ID_E, "address": hex(addr_e)},
            ],
            handoff_files("handoff-dddd-v1.elf", "handoff-eeee.elf"),
        )
    assert any("Build ID 集合" in e for e in exc.value.errors)
    # 原单仍是单帧、单绑定
    assert store.get_report_raw(report_id)["frames"] and len(
        store.get_report_raw(report_id)["frames"]
    ) == 1


def test_failed_handoff_after_success_leaves_no_extra_rows(store, data_dir):
    report_id, _ = _first_handoff(store)
    import os

    before_files = set(os.listdir(store.elf_dir))
    with pytest.raises(HandoffRejected):
        store.intake_handoff(
            "site-A", "ORIG-BAD",
            make_frames(BUILD_ID_D, 0x1000),
            handoff_files("handoff-dddd-v1.elf", "handoff-dddd-v2.elf"),  # 同单冲突
        )
    # 报告/绑定数量不变，磁盘无新增残留（含暂存文件）
    assert store._conn.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"] == 1
    assert store._conn.execute("SELECT COUNT(*) n FROM report_elfs").fetchone()["n"] == 1
    assert set(os.listdir(store.elf_dir)) == before_files
    # 原报告仍可正常解析
    assert store.resolve_report(report_id)["frames"][0]["status"] == "resolved"


def test_uppercase_build_id_normalized_for_binding_and_replay(store):
    addr = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    result = store.intake_handoff(
        "site-A", "ORIG-UPPER",
        [{"build_id": BUILD_ID_D.upper(), "address": hex(addr)}],
        handoff_files("handoff-dddd-v1.elf"),
    )
    assert result["frames"][0]["status"] == "resolved"
    # 小写形式重送视为同一 Build ID，幂等
    again = store.intake_handoff(
        "site-A", "ORIG-UPPER",
        [{"build_id": BUILD_ID_D, "address": hex(addr)}],
        handoff_files("handoff-dddd-v1.elf"),
    )
    assert again["idempotent_replay"] is True


# ---------------------------------------------------------------------------
# 4. 同 Build ID 异内容：报告级绑定隔离
# ---------------------------------------------------------------------------
def test_two_reports_same_buildid_different_elf_resolve_own_files(store):
    addr_v1 = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    addr_v2 = func_address(FIX / "handoff-dddd-v2.elf", "handoff_origin_func")
    r1 = store.intake_handoff(
        "site-A", "R-1", make_frames(BUILD_ID_D, addr_v1),
        handoff_files("handoff-dddd-v1.elf"),
    )["report_id"]
    r2 = store.intake_handoff(
        "site-B", "R-1", make_frames(BUILD_ID_D, addr_v2),
        handoff_files("handoff-dddd-v2.elf"),
    )["report_id"]
    assert r1 != r2

    # v2 独有的函数只能在 r2 解析到；缓存不得因 Build ID 相同而串用
    extra_addr = func_address(FIX / "handoff-dddd-v2.elf", "handoff_extra_func")
    f1 = store.resolve_report(r1)["frames"][0]
    f2 = store.resolve_report(r2)["frames"][0]
    assert f1["source_file"].endswith("handoff_v1.c")
    assert f2["source_file"].endswith("handoff_v2.c")

    # 用 v2 的地址查 r1（绑定 v1）：v1 无此范围，应未解析，证明未串文件
    probe = store.intake_handoff(
        "site-A", "R-PROBE", make_frames(BUILD_ID_D, 0xFFFFF0),
        handoff_files("handoff-dddd-v1.elf"),
    )["report_id"]
    assert store.resolve_report(probe)["frames"][0]["status"] == "unresolved"
    probe2 = store.intake_handoff(
        "site-B", "R-PROBE", make_frames(BUILD_ID_D, extra_addr),
        handoff_files("handoff-dddd-v2.elf"),
    )["report_id"]
    assert store.resolve_report(probe2)["frames"][0]["function"] == "handoff_extra_func"


def test_interleaved_queries_use_own_bound_files(store):
    """交错查栈：两个报告的解析在同进程内交替进行，结果各自正确。"""
    addr_v1 = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    addr_v2 = func_address(FIX / "handoff-dddd-v2.elf", "handoff_origin_func")
    r1 = store.intake_handoff(
        "site-A", "R-1", make_frames(BUILD_ID_D, addr_v1),
        handoff_files("handoff-dddd-v1.elf"),
    )["report_id"]
    r2 = store.intake_handoff(
        "site-B", "R-1", make_frames(BUILD_ID_D, addr_v2),
        handoff_files("handoff-dddd-v2.elf"),
    )["report_id"]

    outcomes: dict[int, str] = {}
    barrier = threading.Barrier(2)

    def query(rid: int, expect_suffix: str):
        barrier.wait()
        # 多次交错，放大缓存串用的概率
        for _ in range(20):
            f = store.resolve_report(rid)["frames"][0]
            assert f["source_file"].endswith(expect_suffix)
        outcomes[rid] = expect_suffix

    t1 = threading.Thread(target=query, args=(r1, "handoff_v1.c"))
    t2 = threading.Thread(target=query, args=(r2, "handoff_v2.c"))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert outcomes == {r1: "handoff_v1.c", r2: "handoff_v2.c"}


def test_handoff_bindings_isolated_from_published_symbols(store):
    """普通报告只用已发布符号；移交报告只用随单绑定，两个符号池互不可见。"""
    addr_d = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    # 先发布 Build ID A 的普通符号
    store.publish_batch([("demo.elf", read_fixture("demo-aaaa.elf"))])

    # 移交报告绑定 D：已发布符号池里没有 D，也不允许用 A 兜底
    handoff = store.intake_handoff(
        "site-A", "R-ISO", make_frames(BUILD_ID_D, addr_d),
        handoff_files("handoff-dddd-v1.elf"),
    )
    assert handoff["resolved_count"] == 1
    assert handoff["snapshot_symbol_version"] == 1  # 记录移交时的全局版本

    # 普通报告引用 D：已发布池中不存在，保持未解析（看不到移交绑定）
    normal_id = store.create_report(make_frames(BUILD_ID_D, addr_d))
    normal = store.resolve_report(normal_id)
    assert normal["frames"][0]["status"] == "unresolved"
    assert normal["frames"][0]["reason"] == "build_id_not_published_at_snapshot"

    # 再发布 D 到公共符号池也不影响既有移交报告的绑定
    store.publish_batch([("h.elf", read_fixture("handoff-dddd-v2.elf"))])
    again = store.resolve_report(handoff["report_id"])
    assert again["frames"][0]["source_file"].endswith("handoff_v1.c")
    # 普通报告现在走公共池，解析到的是后发布的 v2
    normal_after = store.resolve_report(normal_id)
    assert normal_after["frames"][0]["source_file"].endswith("handoff_v2.c")


# ---------------------------------------------------------------------------
# 5. 重启持久化
# ---------------------------------------------------------------------------
def test_handoff_state_and_idempotency_survive_restart(data_dir):
    addr = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    s1 = Store(data_dir=data_dir)
    first = s1.intake_handoff(
        "site-A", "ORIG-R", make_frames(BUILD_ID_D, addr),
        handoff_files("handoff-dddd-v1.elf"),
    )
    report_id = first["report_id"]
    s1.close()

    s2 = Store(data_dir=data_dir)
    try:
        result = s2.resolve_report(report_id)
        assert result["frames"][0]["function"] == "handoff_origin_func"
        assert result["handoff"]["original_report_no"] == "ORIG-R"
        # 重启后幂等重送仍返回原本地号
        replay = s2.intake_handoff(
            "site-A", "ORIG-R", make_frames(BUILD_ID_D, addr),
            handoff_files("handoff-dddd-v1.elf"),
        )
        assert replay["idempotent_replay"] is True
        assert replay["report_id"] == report_id
        # 异内容重送仍拒收
        with pytest.raises(HandoffConflict):
            s2.intake_handoff(
                "site-A", "ORIG-R", make_frames(BUILD_ID_D, addr),
                handoff_files("handoff-dddd-v2.elf"),
            )
    finally:
        s2.close()


def test_restart_keeps_two_same_buildid_reports_isolated(data_dir):
    addr_v1 = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    addr_v2 = func_address(FIX / "handoff-dddd-v2.elf", "handoff_origin_func")
    s1 = Store(data_dir=data_dir)
    r1 = s1.intake_handoff(
        "site-A", "R-1", make_frames(BUILD_ID_D, addr_v1),
        handoff_files("handoff-dddd-v1.elf"),
    )["report_id"]
    r2 = s1.intake_handoff(
        "site-B", "R-1", make_frames(BUILD_ID_D, addr_v2),
        handoff_files("handoff-dddd-v2.elf"),
    )["report_id"]
    s1.close()

    s2 = Store(data_dir=data_dir)
    try:
        f1 = s2.resolve_report(r1)["frames"][0]
        f2 = s2.resolve_report(r2)["frames"][0]
        assert f1["source_file"].endswith("handoff_v1.c")
        assert f2["source_file"].endswith("handoff_v2.c")
    finally:
        s2.close()


# ---------------------------------------------------------------------------
# 6. HTTP multipart 接口
# ---------------------------------------------------------------------------
def _post_handoff(client, source, original_no, frames, file_names):
    files = [
        ("files", (name, read_fixture(name), "application/octet-stream"))
        for name in file_names
    ]
    import json as _json

    return client.post(
        "/handoffs",
        data={
            "source_instance": source,
            "original_report_no": original_no,
            "frames": _json.dumps(frames),
        },
        files=files,
    )


def test_http_handoff_full_lifecycle(client):
    c, store = client
    addr = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
    frames = make_frames(BUILD_ID_D, addr)

    r1 = _post_handoff(c, "site-A", "ORIG-9", frames, ["handoff-dddd-v1.elf"])
    assert r1.status_code == 201
    body1 = r1.json()
    assert body1["idempotent_replay"] is False
    assert body1["frames"][0]["function"] == "handoff_origin_func"
    local_id = body1["report_id"]

    # 完全一致重送：200 + 原本地号
    r2 = _post_handoff(c, "site-A", "ORIG-9", frames, ["handoff-dddd-v1.elf"])
    assert r2.status_code == 200
    assert r2.json()["report_id"] == local_id
    assert r2.json()["idempotent_replay"] is True

    # 内容变化重送：409，原报告不受影响
    r3 = _post_handoff(c, "site-A", "ORIG-9", frames, ["handoff-dddd-v2.elf"])
    assert r3.status_code == 409
    assert "冲突" in r3.json()["detail"]["message"]
    assert c.get(f"/reports/{local_id}").json()["frames"][0]["source_file"].endswith(
        "handoff_v1.c"
    )

    # 不同来源同号：各自本地号
    r4 = _post_handoff(c, "site-B", "ORIG-9", frames, ["handoff-dddd-v2.elf"])
    assert r4.status_code == 201
    assert r4.json()["report_id"] != local_id
    assert r4.json()["frames"][0]["source_file"].endswith("handoff_v2.c")


def test_http_handoff_validation_errors(client):
    c, _store = client
    addr = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")

    # frames 不是合法 JSON
    r = c.post(
        "/handoffs",
        data={"source_instance": "s", "original_report_no": "n", "frames": "{not json"},
        files=[],
    )
    assert r.status_code == 422

    # 缺随单文件
    r = _post_handoff(
        c, "site-A", "ORIG-BAD", make_frames(BUILD_ID_D, addr), []
    )
    assert r.status_code == 422
    assert any("缺少随单 ELF" in e for e in r.json()["detail"]["errors"])

    # 坏 ELF（strip 掉调试信息）
    r = c.post(
        "/handoffs",
        data={
            "source_instance": "site-A",
            "original_report_no": "ORIG-BAD2",
            "frames": __import__("json").dumps(make_frames("c" * 40, addr)),
        },
        files=[("files", ("x.elf", read_fixture("stripped-cccc.elf"), "application/octet-stream"))],
    )
    assert r.status_code == 422
    assert any("调试信息" in e for e in r.json()["detail"]["errors"])


def test_http_handoff_interleaved_through_uvicorn(data_dir):
    """真实 uvicorn 进程：两份同号异内容移交报告交错查栈，各自解析随单文件。"""
    import socket
    import uvicorn
    from app.main import app

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                httpx.get(f"{base}/health", timeout=1)
                break
            except httpx.HTTPError:
                time.sleep(0.1)

        import json as _json

        addr_v1 = func_address(FIX / "handoff-dddd-v1.elf", "handoff_origin_func")
        addr_v2 = func_address(FIX / "handoff-dddd-v2.elf", "handoff_origin_func")

        def send(source, original, addr, elf_name):
            with open(FIX / elf_name, "rb") as fh:
                resp = httpx.post(
                    f"{base}/handoffs",
                    data={
                        "source_instance": source,
                        "original_report_no": original,
                        "frames": _json.dumps(make_frames(BUILD_ID_D, addr)),
                    },
                    files=[("files", (elf_name, fh.read(), "application/octet-stream"))],
                    timeout=15,
                )
            assert resp.status_code == 201, resp.text
            return resp.json()["report_id"]

        r1 = send("site-A", "ORIG-H", addr_v1, "handoff-dddd-v1.elf")
        r2 = send("site-B", "ORIG-H", addr_v2, "handoff-dddd-v2.elf")

        # 交错查询
        for _ in range(10):
            q1 = httpx.get(f"{base}/reports/{r1}", timeout=10).json()
            q2 = httpx.get(f"{base}/reports/{r2}", timeout=10).json()
            assert q1["frames"][0]["source_file"].endswith("handoff_v1.c")
            assert q2["frames"][0]["source_file"].endswith("handoff_v2.c")
            assert q1["handoff"]["bound_build_ids"] == [BUILD_ID_D]

        # 幂等重送（HTTP 200）与冲突（409）
        with open(FIX / "handoff-dddd-v1.elf", "rb") as fh:
            replay = httpx.post(
                f"{base}/handoffs",
                data={
                    "source_instance": "site-A",
                    "original_report_no": "ORIG-H",
                    "frames": _json.dumps(make_frames(BUILD_ID_D, addr_v1)),
                },
                files=[("files", ("v1.elf", fh.read(), "application/octet-stream"))],
                timeout=15,
            )
        assert replay.status_code == 200
        assert replay.json()["report_id"] == r1
    finally:
        server.should_exit = True
        thread.join(timeout=10)
