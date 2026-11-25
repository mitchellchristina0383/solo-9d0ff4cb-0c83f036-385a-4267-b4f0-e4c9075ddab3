"""FastAPI 入口：崩溃栈提交、按报告号查询、CI 批量补传 ELF。"""
from __future__ import annotations

from contextlib import asynccontextmanager
import json
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import settings
from .storage import BatchRejected, HandoffConflict, HandoffRejected, Store

_store: Optional[Store] = None


def get_store() -> Store:
    # 测试可通过 dependency_overrides 替换
    if _store is None:
        raise RuntimeError("Store 尚未初始化")
    return _store


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _store
    _store = Store()
    yield
    if _store is not None:
        _store.close()
        _store = None


app = FastAPI(
    title="Linux 崩溃栈还原服务",
    version=__version__,
    description=(
        "值班员提交各帧的 ELF Build ID 与扣除装载偏移后的地址，凭报告号查询函数与源码行；"
        "CI 可批量补传带 Build ID 与 DWARF 调试信息的 x86-64 ELF。"
        "查询绑定开始解析时的符号版本快照，查栈与发布可并行。"
        "另有 /handoffs 跨实例移交接口：来源实例、原报告号、原始帧与随单 ELF "
        "原子登记，随单 ELF 与报告绑定、与公共符号池隔离。"
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# 请求/响应模型
# ---------------------------------------------------------------------------
class FrameIn(BaseModel):
    build_id: Optional[str] = Field(
        default=None,
        description="GNU Build ID（十六进制，不带 0x）；未知时可留空，该帧保留原地址",
    )
    address: str = Field(
        ...,
        description="已扣除装载偏移的地址，支持 0x 前缀十六进制或十进制字符串",
    )


class ReportIn(BaseModel):
    frames: List[FrameIn] = Field(..., min_length=1, description="崩溃栈各帧，自底向上或自顶向下均可，按提交顺序保存")


class FrameOut(BaseModel):
    position: int
    build_id: Optional[str]
    address: str
    status: str
    reason: Optional[str]
    function: Optional[str]
    source_file: Optional[str]
    source_line: Optional[int]


class HandoffInfo(BaseModel):
    source_instance: str
    original_report_no: str
    bound_build_ids: List[str]


class BatchResult(BaseModel):
    accepted: int
    new_build_ids: List[str]
    redundant: int
    symbol_version: int


class ReportOut(BaseModel):
    report_id: int
    created_at: str
    snapshot_symbol_version: int
    current_symbol_version: int
    frame_count: int
    resolved_count: int
    frames: List[FrameOut]
    handoff: Optional[HandoffInfo] = None


class HandoffOut(ReportOut):
    """移交登记结果：在普通报告解析结果上附加移交元数据与幂等标记。"""

    source_instance: str
    original_report_no: str
    idempotent_replay: bool = Field(
        ..., description="true 表示同来源同原报告号重送且内容一致，返回的是原本地号"
    )


# ---------------------------------------------------------------------------
# 接口
# ---------------------------------------------------------------------------
@app.get("/health", tags=["运维"])
def health():
    store = get_store()
    return {
        "status": "ok",
        "version": __version__,
        "symbol_version": store.symbol_version,
        "published_build_ids": len(store.list_build_ids()),
        "data_dir": settings.data_dir,
    }


@app.post("/reports", response_model=ReportOut, status_code=201, tags=["崩溃报告"])
def submit_report(payload: ReportIn):
    """提交崩溃栈并立即按当前已发布符号做一次解析，返回报告号。"""
    store = get_store()
    frames = [f.model_dump() for f in payload.frames]
    report_id = store.create_report(frames)
    return store.resolve_report(report_id)


@app.get("/reports/{report_id}", response_model=ReportOut, tags=["崩溃报告"])
def get_report(report_id: int):
    """凭报告号查询；补传 ELF 后用同一报告号再查即可得到新解析结果。

    每次查询只使用本次开始解析时已发布的符号版本（快照）。
    """
    store = get_store()
    result = store.resolve_report(report_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"报告 {report_id} 不存在")
    return result


@app.get("/reports/{report_id}/raw", tags=["崩溃报告"])
def get_report_raw(report_id: int):
    """查看报告原始帧（地址原样保留）。"""
    store = get_store()
    raw = store.get_report_raw(report_id)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"报告 {report_id} 不存在")
    return raw


@app.post("/handoffs", response_model=HandoffOut, tags=["跨实例移交"])
def intake_handoff(
    source_instance: str = Form(..., description="来源实例标识，如对端值班员实例名/主机名"),
    original_report_no: str = Form(..., description="来源实例上的原报告号（字符串）"),
    frames: str = Form(
        ...,
        description=(
            "原始帧 JSON 数组，每项 {\"build_id\": 十六进制串或 null, "
            "\"address\": \"0x.. 或十进制字符串\"}，原样持久化"
        ),
    ),
    files: List[UploadFile] = File(
        default_factory=list,
        description=(
            "随单 ELF：帧中每个非空 Build ID 都须有一个通过同款校验"
            "（x86-64、含 Build ID 与 DWARF）的对应文件"
        ),
    ),
):
    """跨实例移交崩溃报告：登记来源实例、原报告号、原始帧与随单 ELF。

    规则：

    - 每个非空 Build ID 都须有通过原有校验的对应 ELF，同单内同 Build ID
      出现内容不同的文件整单拒收（422）；
    - 报告与符号绑定在同一事务登记，校验失败不留任何可查报告或绑定；
    - 不同来源的同号报告各自分配本地报告号；同一来源同一原报告号重送时，
      帧与各 Build ID 对应文件内容全部一致才返回原本地号（200，
      idempotent_replay=true），有任何变化则拒收（409）；
    - 随单 ELF 仅与本报告绑定：两份报告可各持同 Build ID 的不同 ELF，
      交错查栈或重启后仍解析各自的文件；普通报告继续只使用 /symbols 发布的符号。
    """
    try:
        parsed_frames = json.loads(frames)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"frames 不是合法 JSON: {exc}")
    if not isinstance(parsed_frames, list) or not parsed_frames:
        raise HTTPException(status_code=422, detail="frames 必须是非空 JSON 数组")
    if not all(isinstance(f, dict) and "address" in f for f in parsed_frames):
        raise HTTPException(status_code=422, detail="frames 每项须为含 address 的对象")

    blobs: list[tuple[str, bytes]] = []
    for upload in files:
        blob = upload.file.read()
        if not blob:
            raise HTTPException(
                status_code=422, detail=f"文件 {upload.filename} 为空"
            )
        blobs.append((upload.filename or "unnamed", blob))

    store = get_store()
    try:
        result = store.intake_handoff(
            source_instance, original_report_no, parsed_frames, blobs
        )
    except HandoffConflict as exc:
        raise HTTPException(
            status_code=409, detail={"message": "重送内容与原单冲突，已拒收", "errors": exc.errors}
        )
    except HandoffRejected as exc:
        raise HTTPException(
            status_code=422, detail={"message": "移交单整单退回", "errors": exc.errors}
        )
    # 首送 201；幂等重送 200，响应体仍为同一本地报告号的完整解析结果
    return JSONResponse(
        content=HandoffOut(**result).model_dump(),
        status_code=200 if result.get("idempotent_replay") else 201,
    )


@app.post("/symbols/batch", response_model=BatchResult, tags=["符号发布"])
def upload_batch(files: List[UploadFile] = File(..., description="一批 x86-64 ELF 文件")):
    """CI 整批补传 ELF。

    - Build ID 从文件内部的 NT_GNU_BUILD_ID 注释读取；
    - 任一文件缺标识、缺调试信息、非 x86-64，或与同 Build ID 已发布/同批文件内容不同，
      整批退回（422），不留任何部分结果；
    - 相同文件重传视为成功，计入 redundant。

    同步端点：阻塞式校验/落盘由 Starlette 放到线程池执行，不卡住事件循环。
    """
    if not files:
        raise HTTPException(status_code=422, detail="未上传任何文件")
    blobs: list[tuple[str, bytes]] = []
    for upload in files:
        blob = upload.file.read()
        if not blob:
            raise HTTPException(status_code=422, detail=f"文件 {upload.filename} 为空")
        blobs.append((upload.filename or "unnamed", blob))

    store = get_store()
    try:
        return store.publish_batch(blobs)
    except BatchRejected as exc:
        raise HTTPException(status_code=422, detail={"message": "整批退回", "errors": exc.errors})


@app.get("/symbols", tags=["符号发布"])
def list_symbols():
    """列出当前已发布的 Build ID。"""
    store = get_store()
    return {"symbol_version": store.symbol_version, "build_ids": store.list_build_ids()}
