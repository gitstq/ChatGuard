"""
审计日志系统模块

提供全面的审计日志记录、存储和查询功能，支持合规审计需求。
"""

import json
import hashlib
import threading
from enum import Enum, auto
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Any, Union
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3


class AuditLevel(Enum):
    """审计日志级别"""
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @property
    def value_name(self) -> str:
        """获取级别的字符串名称"""
        names = {
            10: "debug",
            20: "info",
            30: "warning",
            40: "error",
            50: "critical",
        }
        return names.get(self.value, "unknown")

    @classmethod
    def from_name(cls, name: str) -> "AuditLevel":
        """从字符串名称获取枚举值"""
        name_map = {
            "debug": cls.DEBUG,
            "info": cls.INFO,
            "warning": cls.WARNING,
            "error": cls.ERROR,
            "critical": cls.CRITICAL,
        }
        return name_map.get(name.lower(), cls.INFO)


class AuditEventType(Enum):
    """审计事件类型"""
    CONTENT_SCAN = "content_scan"
    RULE_MATCH = "rule_match"
    POLICY_VIOLATION = "policy_violation"
    ACCESS_DENIED = "access_denied"
    CONFIG_CHANGE = "config_change"
    USER_ACTION = "user_action"
    SYSTEM_EVENT = "system_event"
    COMPLIANCE_CHECK = "compliance_check"


@dataclass
class AuditEntry:
    """审计日志条目"""
    id: str
    timestamp: datetime
    level: AuditLevel
    event_type: AuditEventType
    source: str
    message: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    content_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    hash: Optional[str] = None

    def __post_init__(self):
        """初始化后计算哈希"""
        if self.hash is None:
            self.hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """计算日志条目的哈希值（用于完整性验证）"""
        data = {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value_name,
            "event_type": self.event_type.value,
            "source": self.source,
            "message": self.message,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "content_id": self.content_id,
            "metadata": self.metadata,
        }
        json_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value_name,
            "event_type": self.event_type.value,
            "source": self.source,
            "message": self.message,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "content_id": self.content_id,
            "metadata": self.metadata,
            "hash": self.hash,
        }

    def to_json(self) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def verify_integrity(self) -> bool:
        """验证日志条目完整性"""
        return self.hash == self._calculate_hash()


class AuditStorage:
    """审计日志存储基类"""

    def write(self, entry: AuditEntry) -> bool:
        """写入日志条目"""
        raise NotImplementedError

    def read(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        level: Optional[AuditLevel] = None,
        event_type: Optional[AuditEventType] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """读取日志条目"""
        raise NotImplementedError

    def close(self) -> None:
        """关闭存储"""
        pass


class FileAuditStorage(AuditStorage):
    """文件存储后端"""

    def __init__(self, filepath: Union[str, Path], rotate_size: int = 10 * 1024 * 1024):
        self.filepath = Path(filepath)
        self.rotate_size = rotate_size
        self._lock = threading.Lock()
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        """确保目录存在"""
        self.filepath.parent.mkdir(parents=True, exist_ok=True)

    def _get_current_file(self) -> Path:
        """获取当前日志文件路径"""
        if not self.filepath.exists():
            return self.filepath

        if self.filepath.stat().st_size < self.rotate_size:
            return self.filepath

        # 轮转文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated = self.filepath.parent / f"{self.filepath.stem}_{timestamp}{self.filepath.suffix}"
        self.filepath.rename(rotated)
        return self.filepath

    def write(self, entry: AuditEntry) -> bool:
        """写入日志条目"""
        try:
            with self._lock:
                filepath = self._get_current_file()
                with open(filepath, "a", encoding="utf-8") as f:
                    f.write(entry.to_json() + "\n")
            return True
        except Exception as e:
            print(f"Failed to write audit log: {e}")
            return False

    def read(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        level: Optional[AuditLevel] = None,
        event_type: Optional[AuditEventType] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """读取日志条目"""
        entries = []

        if not self.filepath.exists():
            return entries

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                        entry = self._dict_to_entry(data)

                        # 过滤条件
                        if start_time and entry.timestamp < start_time:
                            continue
                        if end_time and entry.timestamp > end_time:
                            continue
                        if level and entry.level != level:
                            continue
                        if event_type and entry.event_type != event_type:
                            continue

                        entries.append(entry)

                        if len(entries) >= limit:
                            break
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Failed to read audit log: {e}")

        return entries

    def _dict_to_entry(self, data: Dict[str, Any]) -> AuditEntry:
        """字典转换为AuditEntry"""
        return AuditEntry(
            id=data["id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            level=AuditLevel.from_name(data["level"]),
            event_type=AuditEventType(data["event_type"]),
            source=data["source"],
            message=data["message"],
            user_id=data.get("user_id"),
            session_id=data.get("session_id"),
            content_id=data.get("content_id"),
            metadata=data.get("metadata", {}),
            hash=data.get("hash"),
        )


class SQLiteAuditStorage(AuditStorage):
    """SQLite存储后端"""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """初始化数据库"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    message TEXT NOT NULL,
                    user_id TEXT,
                    session_id TEXT,
                    content_id TEXT,
                    metadata TEXT,
                    hash TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_level ON audit_logs(level)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_event_type ON audit_logs(event_type)
            """)
            conn.commit()

    def write(self, entry: AuditEntry) -> bool:
        """写入日志条目"""
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO audit_logs
                        (id, timestamp, level, event_type, source, message, user_id, session_id, content_id, metadata, hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        entry.id,
                        entry.timestamp.isoformat(),
                        entry.level.value_name,
                        entry.event_type.value,
                        entry.source,
                        entry.message,
                        entry.user_id,
                        entry.session_id,
                        entry.content_id,
                        json.dumps(entry.metadata, ensure_ascii=False),
                        entry.hash,
                    ))
                    conn.commit()
            return True
        except Exception as e:
            print(f"Failed to write audit log: {e}")
            return False

    def read(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        level: Optional[AuditLevel] = None,
        event_type: Optional[AuditEventType] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """读取日志条目"""
        entries = []

        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        if level:
            query += " AND level = ?"
            params.append(level.value_name)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)

                for row in cursor:
                    entries.append(AuditEntry(
                        id=row["id"],
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        level=AuditLevel.from_name(row["level"]),
                        event_type=AuditEventType(row["event_type"]),
                        source=row["source"],
                        message=row["message"],
                        user_id=row["user_id"],
                        session_id=row["session_id"],
                        content_id=row["content_id"],
                        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                        hash=row["hash"],
                    ))
        except Exception as e:
            print(f"Failed to read audit log: {e}")

        return entries


class AuditLogger:
    """审计日志记录器"""

    def __init__(self, storage: Optional[AuditStorage] = None):
        self.storage = storage or FileAuditStorage("audit.log")
        self._callbacks: List[Callable[[AuditEntry], None]] = []
        self._counter = 0
        self._counter_lock = threading.Lock()
        self._min_level = AuditLevel.DEBUG

    def set_min_level(self, level: AuditLevel) -> None:
        """设置最小记录级别"""
        self._min_level = level

    def _generate_id(self) -> str:
        """生成唯一ID"""
        with self._counter_lock:
            self._counter += 1
            counter = self._counter
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"AUDIT-{timestamp}-{counter:08d}"

    def log(
        self,
        level: AuditLevel,
        event_type: AuditEventType,
        source: str,
        message: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        content_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[AuditEntry]:
        """
        记录审计日志

        Args:
            level: 日志级别
            event_type: 事件类型
            source: 来源标识
            message: 日志消息
            user_id: 用户ID
            session_id: 会话ID
            content_id: 内容ID
            metadata: 元数据

        Returns:
            AuditEntry: 创建的日志条目，如果级别不足则返回None
        """
        # 检查级别
        if level.value < self._min_level.value:
            return None

        entry = AuditEntry(
            id=self._generate_id(),
            timestamp=datetime.now(),
            level=level,
            event_type=event_type,
            source=source,
            message=message,
            user_id=user_id,
            session_id=session_id,
            content_id=content_id,
            metadata=metadata or {},
        )

        # 写入存储
        if self.storage.write(entry):
            # 触发回调
            for callback in self._callbacks:
                try:
                    callback(entry)
                except Exception as e:
                    print(f"Audit callback error: {e}")
            return entry

        return None

    def debug(
        self,
        event_type: AuditEventType,
        source: str,
        message: str,
        **kwargs,
    ) -> Optional[AuditEntry]:
        """记录DEBUG级别日志"""
        return self.log(AuditLevel.DEBUG, event_type, source, message, **kwargs)

    def info(
        self,
        event_type: AuditEventType,
        source: str,
        message: str,
        **kwargs,
    ) -> Optional[AuditEntry]:
        """记录INFO级别日志"""
        return self.log(AuditLevel.INFO, event_type, source, message, **kwargs)

    def warning(
        self,
        event_type: AuditEventType,
        source: str,
        message: str,
        **kwargs,
    ) -> Optional[AuditEntry]:
        """记录WARNING级别日志"""
        return self.log(AuditLevel.WARNING, event_type, source, message, **kwargs)

    def error(
        self,
        event_type: AuditEventType,
        source: str,
        message: str,
        **kwargs,
    ) -> Optional[AuditEntry]:
        """记录ERROR级别日志"""
        return self.log(AuditLevel.ERROR, event_type, source, message, **kwargs)

    def critical(
        self,
        event_type: AuditEventType,
        source: str,
        message: str,
        **kwargs,
    ) -> Optional[AuditEntry]:
        """记录CRITICAL级别日志"""
        return self.log(AuditLevel.CRITICAL, event_type, source, message, **kwargs)

    def add_callback(self, callback: Callable[[AuditEntry], None]) -> None:
        """添加日志回调"""
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[AuditEntry], None]) -> bool:
        """移除回调"""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
            return True
        return False

    def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        level: Optional[AuditLevel] = None,
        event_type: Optional[AuditEventType] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """查询日志"""
        return self.storage.read(start_time, end_time, level, event_type, limit)

    def get_recent(self, hours: int = 24, limit: int = 100) -> List[AuditEntry]:
        """获取最近时间的日志"""
        start_time = datetime.now() - timedelta(hours=hours)
        return self.query(start_time=start_time, limit=limit)

    def get_stats(self, hours: int = 24) -> Dict[str, Any]:
        """获取统计信息"""
        start_time = datetime.now() - timedelta(hours=hours)
        entries = self.query(start_time=start_time, limit=10000)

        stats = {
            "total_entries": len(entries),
            "by_level": {},
            "by_event_type": {},
            "time_range": {
                "start": start_time.isoformat(),
                "end": datetime.now().isoformat(),
            },
        }

        for entry in entries:
            level = entry.level.value_name
            event_type = entry.event_type.value

            stats["by_level"][level] = stats["by_level"].get(level, 0) + 1
            stats["by_event_type"][event_type] = stats["by_event_type"].get(event_type, 0) + 1

        return stats

    def export_to_file(
        self,
        filepath: Union[str, Path],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """导出日志到文件"""
        entries = self.query(start_time=start_time, end_time=end_time, limit=100000)

        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(entry.to_json() + "\n")

        return len(entries)

    def close(self) -> None:
        """关闭日志记录器"""
        if self.storage:
            self.storage.close()
