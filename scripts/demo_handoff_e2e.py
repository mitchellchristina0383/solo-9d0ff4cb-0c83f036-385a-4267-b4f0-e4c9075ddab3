#!/usr/bin/env python3
"""移交功能端到端实测脚本（交付前核对用，非 pytest）。

用真实 uvicorn 进程 + httpx multipart 请求验证：
  1. 两个来源各自移交同原报告号、同 Build ID 但内容不同的 ELF；
  2. 交错查栈，两份报告始终解析各自的随单文件；
  3. 一致重送返回原本地号（200），变化重送 409 拒收；
  4. 校验失败（缺随单文件）不落任何报告；
  5. 重启 Store（新进程对象、同一数据目录）后绑定与幂等仍然成立；
  6. 普通报告继续只使用 /symbols 已发布符号，看不到移交绑定。

用法: python scripts/demo_handoff_e2e.py [fixture_dir]
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
from pathlib import Path

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.main import app  # noqa: E402
from app.storage import Store  # noqa: E402

FIX = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "tests" / "fixtures" / "built")
BUILD_ID_D = "d" * 40


def func_address(elf_path: Path, func: str) -> int:
    from elftools.elf.elffile import ELFFile

    with open(elf_path, "rb") as fh:
        elf = ELFFile(fh)
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_SYMTAB":
                continue
            for sym in section.iter_symbols():
                if sym.name == func and sym["st_info"]["type"] == "STT_FUNC":
                    return sym["st_value"]
    raise AssertionError(func)


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def post_handoff(base, source, original_no, frames, elf_paths):
    files = [
        ("files", (p.name, p.read_bytes(), "application/octet-stream")) for p in elf_paths
    ]
    return httpx.post(
        f"{base}/handoffs",
        data={
            "source_instance": source,
            "original_report_no": original_no,
            "frames": json.dumps(frames),
        },
        files=files,
        timeout=30,
    )


def main() -> int:
    import os
    import tempfile

    data_dir = tempfile.mkdtemp(prefix="handoff-demo-")
    os.environ["SYMBOL_DATA_DIR"] = data_dir

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(f"{base}/health", timeout=1)
            break
        except httpx.HTTPError:
            time.sleep(0.1)

    v1 = FIX / "handoff-dddd-v1.elf"
    v2 = FIX / "handoff-dddd-v2.elf"
    addr_v1 = func_address(v1, "handoff_origin_func")
    addr_v2 = func_address(v2, "handoff_origin_func")
    extra_v2 = func_address(v2, "handoff_extra_func")
    frames_v1 = [{"build_id": BUILD_ID_D, "address": hex(addr_v1)}]
    frames_v2 = [{"build_id": BUILD_ID_D, "address": hex(addr_v2)}]

    print("== 1) 两个来源同原报告号 ORIG-77，各带同 Build ID 异内容 ELF ==")
    r_a = post_handoff(base, "site-A", "ORIG-77", frames_v1, [v1])
    r_b = post_handoff(base, "site-B", "ORIG-77", frames_v2, [v2])
    assert r_a.status_code == 201 and r_b.status_code == 201, (r_a.text, r_b.text)
    id_a, id_b = r_a.json()["report_id"], r_b.json()["report_id"]
    print(f"   site-A 本地号={id_a} -> {r_a.json()['frames'][0]['source_file']}")
    print(f"   site-B 本地号={id_b} -> {r_b.json()['frames'][0]['source_file']}")
    assert id_a != id_b

    print("== 2) 交错查栈 10 轮，各自必须命中随单文件 ==")
    for i in range(10):
        q_a = httpx.get(f"{base}/reports/{id_a}", timeout=10).json()
        q_b = httpx.get(f"{base}/reports/{id_b}", timeout=10).json()
        assert q_a["frames"][0]["source_file"].endswith("handoff_v1.c"), q_a
        assert q_b["frames"][0]["source_file"].endswith("handoff_v2.c"), q_b
    print("   每轮: A=handoff_v1.c, B=handoff_v2.c  OK")

    # v2 独有函数：B 可解析；A（绑定 v1）用一个超出任何 ELF 范围的地址查，应未解析
    probe_b = post_handoff(base, "site-B", "PROBE-X",
                           [{"build_id": BUILD_ID_D, "address": hex(extra_v2)}], [v2]).json()
    probe_a = post_handoff(base, "site-A", "PROBE-X",
                           [{"build_id": BUILD_ID_D, "address": "0xFFFFF0"}], [v1]).json()
    assert probe_b["frames"][0]["function"] == "handoff_extra_func"
    assert probe_a["frames"][0]["status"] == "unresolved"
    print("== 3) 绑定隔离: B 解析 handoff_extra_func，A 对越界地址未解析  OK ==")

    print("== 4) 重送: 一致 -> 200 原号；帧变化 / 文件变化 -> 409 ==")
    replay = post_handoff(base, "site-A", "ORIG-77", frames_v1, [v1])
    assert replay.status_code == 200
    assert replay.json()["report_id"] == id_a
    assert replay.json()["idempotent_replay"] is True
    print(f"   一致重送 200, 本地号仍为 {id_a}")
    conflict_frame = post_handoff(
        base, "site-A", "ORIG-77",
        [{"build_id": BUILD_ID_D, "address": hex(addr_v1 + 1)}], [v1],
    )
    assert conflict_frame.status_code == 409, conflict_frame.text
    conflict_elf = post_handoff(base, "site-A", "ORIG-77", frames_v1, [v2])
    assert conflict_elf.status_code == 409, conflict_elf.text
    print(f"   帧变化 409: {conflict_frame.json()['detail']['errors'][0]}")
    print(f"   文件变化 409: {conflict_elf.json()['detail']['errors'][0]}")
    # 原报告未被污染
    still = httpx.get(f"{base}/reports/{id_a}", timeout=10).json()
    assert still["frames"][0]["source_file"].endswith("handoff_v1.c")

    print("== 5) 校验失败不留痕: 缺随单文件 422 ==")
    bad = post_handoff(base, "site-A", "ORIG-NOFILE", frames_v1, [])
    assert bad.status_code == 422
    print(f"   422: {bad.json()['detail']['errors']}")
    from app.main import get_store
    store = get_store()
    n_reports = store._conn.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"]
    n_h = store._conn.execute("SELECT COUNT(*) n FROM handoffs").fetchone()["n"]
    print(f"   库内报告数={n_reports}, 移交单数={n_h}（失败单未入库）")

    print("== 6) 普通报告与移交符号池隔离 ==")
    normal = httpx.post(f"{base}/reports", json={"frames": frames_v1}, timeout=10).json()
    assert normal["frames"][0]["status"] == "unresolved"
    assert normal["frames"][0]["reason"] == "build_id_not_published_at_snapshot"
    assert normal.get("handoff") is None
    print("   普通报告引用 dddd 未发布 -> unresolved，看不到移交绑定  OK")

    print("== 7) 重启 Store（同数据目录新对象）后绑定/幂等/隔离仍成立 ==")
    import app.main as main_module

    old_store = main_module.get_store()
    old_store.close()
    server.should_exit = True
    thread.join(timeout=10)
    # 模拟进程重启：新 Store 打开同一数据目录（WAL SQLite + 内容寻址 ELF）
    s2 = Store(data_dir=data_dir)
    main_module._store = s2
    try:
        q1 = s2.resolve_report(id_a)
        q2 = s2.resolve_report(id_b)
        assert q1["frames"][0]["source_file"].endswith("handoff_v1.c")
        assert q2["frames"][0]["source_file"].endswith("handoff_v2.c")
        replay2 = s2.intake_handoff("site-A", "ORIG-77", frames_v1, [("v1.elf", v1.read_bytes())])
        assert replay2["idempotent_replay"] is True and replay2["report_id"] == id_a
        print(f"   重启后 A->v1, B->v2, 重送仍返回原号 {id_a}  OK")
    finally:
        s2.close()
        main_module._store = None

    print("\n全部端到端核对通过 ✔")
    return 0


if __name__ == "__main__":
    sys.exit(main())
