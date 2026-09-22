"""基于本地 JSON 文件的持久化与并发控制。

设计要点：
- 每个聚合（policies / decisions / exemptions / idempotency）一个 JSON 文件；
- 写入走“临时文件 + os.replace”原子替换，读者只会看到完整文件；
- 进程内用 threading.RLock 串行化，跨进程用 fcntl.flock 排他锁，
  保证并发提交下最终状态唯一确定；
- 仅依赖标准库，数据目录可配置，默认 ./data。
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .errors import StorageError


class JsonStore:
    """带文件锁的 JSON 文档存储，整个文件即一个可原地修改的 dict。"""

    def __init__(self, path: str | Path, *, default: dict[str, Any] | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._default = default or {}
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def load(self) -> dict[str, Any]:
        """读取全部数据（文件不存在或为空时返回默认结构的拷贝）。"""
        with self._lock:
            return self._read_locked()

    def write_all(self, data: dict[str, Any]) -> None:
        """原子写入全部数据（进程内 + 跨进程排他锁）。"""
        with self._lock, self._file_lock():
            self._atomic_write(data)

    @contextlib.contextmanager
    def mutate(self) -> Iterator[dict[str, Any]]:
        """加锁 -> 读取 -> 交给调用方原地修改 -> 退出时原子落盘。

        异常时不写盘。持锁期间的读取一定是最新值，
        配合 check-then-write 保证并发提交的最终状态唯一。
        """
        with self._lock, self._file_lock():
            data = self._read_locked()
            yield data
            self._atomic_write(data)

    # ---- internal ----

    def _read_locked(self) -> dict[str, Any]:
        if not self.path.exists():

            return json.loads(json.dumps(self._default))
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                content = fh.read()
            if not content.strip():
                return json.loads(json.dumps(self._default))
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise StorageError(f"存储文件损坏，无法解析: {self.path}: {exc}") from exc
        if not isinstance(data, dict):
            raise StorageError(f"存储文件根节点必须是对象: {self.path}")
        return data

    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        # 独占锁文件，协调同一台机器上的多个进程
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = self._lock_path.open("a+")
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            yield
        except OSError as exc:
            raise StorageError(f"获取文件锁失败: {self._lock_path}: {exc}") from exc
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            fh.close()

    def _atomic_write(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except OSError as exc:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise StorageError(f"写入存储失败: {self.path}: {exc}") from exc
