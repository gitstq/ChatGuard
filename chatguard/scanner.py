"""
实时扫描器模块

提供实时内容扫描能力，支持流式检测和异步处理。
"""

import asyncio
import queue
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any, AsyncIterator
from datetime import datetime
from enum import Enum, auto
import json

from .detector import ContentDetector, DetectionResult, RiskLevel


class ScanStatus(Enum):
    """扫描状态枚举"""
    PENDING = auto()
    SCANNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class ScanResult:
    """扫描结果数据类"""
    scan_id: str
    content: str
    status: ScanStatus
    detection_result: Optional[DetectionResult] = None
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> Optional[float]:
        """计算扫描耗时"""
        if self.completed_at and self.created_at:
            return (self.completed_at - self.created_at).total_seconds() * 1000
        return None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "scan_id": self.scan_id,
            "content_preview": self.content[:100] + "..." if len(self.content) > 100 else self.content,
            "status": self.status.name,
            "detection_result": self.detection_result.to_dict() if self.detection_result else None,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }


class ScanQueue:
    """扫描任务队列"""

    def __init__(self, max_size: int = 1000):
        self._queue: queue.Queue = queue.Queue(maxsize=max_size)
        self._lock = threading.Lock()
        self._stats = {
            "submitted": 0,
            "processed": 0,
            "failed": 0,
        }

    def submit(self, scan_result: ScanResult) -> bool:
        """提交扫描任务"""
        try:
            self._queue.put_nowait(scan_result)
            with self._lock:
                self._stats["submitted"] += 1
            return True
        except queue.Full:
            return False

    def get(self, timeout: Optional[float] = None) -> Optional[ScanResult]:
        """获取扫描任务"""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def mark_processed(self, success: bool = True) -> None:
        """标记任务已处理"""
        with self._lock:
            if success:
                self._stats["processed"] += 1
            else:
                self._stats["failed"] += 1

    def get_stats(self) -> Dict[str, int]:
        """获取队列统计"""
        with self._lock:
            return self._stats.copy()

    @property
    def size(self) -> int:
        """获取当前队列大小"""
        return self._queue.qsize()


class ContentScanner:
    """内容扫描器"""

    def __init__(
        self,
        detector: Optional[ContentDetector] = None,
        max_workers: int = 4,
        queue_size: int = 1000,
    ):
        self.detector = detector or ContentDetector()
        self.max_workers = max_workers
        self.queue = ScanQueue(max_size=queue_size)
        self._workers: List[threading.Thread] = []
        self._running = False
        self._callbacks: List[Callable[[ScanResult], None]] = []
        self._scan_counter = 0
        self._counter_lock = threading.Lock()

    def start(self) -> None:
        """启动扫描器"""
        if self._running:
            return

        self._running = True
        self._workers = []

        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"ScannerWorker-{i}",
                daemon=True,
            )
            worker.start()
            self._workers.append(worker)

    def stop(self, wait: bool = True, timeout: Optional[float] = None) -> None:
        """停止扫描器"""
        self._running = False

        if wait:
            for worker in self._workers:
                worker.join(timeout=timeout)

        self._workers = []

    def _worker_loop(self) -> None:
        """工作线程主循环"""
        while self._running:
            scan_result = self.queue.get(timeout=1.0)
            if scan_result is None:
                continue

            try:
                self._process_scan(scan_result)
                self.queue.mark_processed(success=True)
            except Exception as e:
                scan_result.status = ScanStatus.FAILED
                scan_result.error_message = str(e)
                scan_result.completed_at = datetime.now()
                self.queue.mark_processed(success=False)
                self._trigger_callbacks(scan_result)

    def _process_scan(self, scan_result: ScanResult) -> None:
        """处理扫描任务"""
        scan_result.status = ScanStatus.SCANNING

        detection_result = self.detector.detect(
            scan_result.content,
            content_id=scan_result.scan_id,
        )

        scan_result.detection_result = detection_result
        scan_result.status = ScanStatus.COMPLETED
        scan_result.completed_at = datetime.now()

        self._trigger_callbacks(scan_result)

    def _trigger_callbacks(self, scan_result: ScanResult) -> None:
        """触发回调函数"""
        for callback in self._callbacks:
            try:
                callback(scan_result)
            except Exception as e:
                print(f"Callback error: {e}")

    def _generate_scan_id(self) -> str:
        """生成扫描ID"""
        with self._counter_lock:
            self._scan_counter += 1
            counter = self._scan_counter
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"SCAN-{timestamp}-{counter:06d}"

    def scan(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        blocking: bool = False,
        timeout: Optional[float] = None,
    ) -> ScanResult:
        """
        提交扫描任务

        Args:
            content: 待扫描内容
            metadata: 元数据
            blocking: 是否阻塞等待结果
            timeout: 超时时间（秒）

        Returns:
            ScanResult: 扫描结果
        """
        scan_result = ScanResult(
            scan_id=self._generate_scan_id(),
            content=content,
            status=ScanStatus.PENDING,
            metadata=metadata or {},
        )

        if blocking:
            # 同步执行
            scan_result.status = ScanStatus.SCANNING
            try:
                self._process_scan(scan_result)
            except Exception as e:
                scan_result.status = ScanStatus.FAILED
                scan_result.error_message = str(e)
                scan_result.completed_at = datetime.now()
        else:
            # 异步提交到队列
            if not self.queue.submit(scan_result):
                scan_result.status = ScanStatus.FAILED
                scan_result.error_message = "Queue is full"
                scan_result.completed_at = datetime.now()

        return scan_result

    def batch_scan(
        self,
        contents: List[str],
        metadata_list: Optional[List[Dict[str, Any]]] = None,
    ) -> List[ScanResult]:
        """批量扫描"""
        results = []
        metadata_list = metadata_list or [None] * len(contents)

        for content, metadata in zip(contents, metadata_list):
            result = self.scan(content, metadata=metadata, blocking=True)
            results.append(result)

        return results

    def add_callback(self, callback: Callable[[ScanResult], None]) -> None:
        """添加扫描完成回调"""
        self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[ScanResult], None]) -> bool:
        """移除回调"""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
            return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """获取扫描器统计"""
        return {
            "running": self._running,
            "workers": len(self._workers),
            "queue_size": self.queue.size,
            "queue_stats": self.queue.get_stats(),
            "detector_stats": self.detector.get_stats(),
        }


class AsyncContentScanner:
    """异步内容扫描器"""

    def __init__(self, detector: Optional[ContentDetector] = None):
        self.detector = detector or ContentDetector()
        self._scan_counter = 0

    async def scan(
        self,
        content: str,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """异步扫描"""
        scan_id = scan_id or self._generate_scan_id()

        scan_result = ScanResult(
            scan_id=scan_id,
            content=content,
            status=ScanStatus.SCANNING,
            metadata=metadata or {},
        )

        try:
            # 在线程池中执行检测
            loop = asyncio.get_event_loop()
            detection_result = await loop.run_in_executor(
                None,
                self.detector.detect,
                content,
                scan_id,
            )

            scan_result.detection_result = detection_result
            scan_result.status = ScanStatus.COMPLETED
        except Exception as e:
            scan_result.status = ScanStatus.FAILED
            scan_result.error_message = str(e)

        scan_result.completed_at = datetime.now()
        return scan_result

    async def batch_scan(
        self,
        contents: List[str],
        metadata_list: Optional[List[Dict[str, Any]]] = None,
    ) -> List[ScanResult]:
        """批量异步扫描"""
        metadata_list = metadata_list or [None] * len(contents)

        tasks = [
            self.scan(content, metadata=metadata)
            for content, metadata in zip(contents, metadata_list)
        ]

        return await asyncio.gather(*tasks)

    async def stream_scan(
        self,
        content_stream: AsyncIterator[str],
    ) -> AsyncIterator[ScanResult]:
        """流式扫描"""
        async for content in content_stream:
            result = await self.scan(content)
            yield result

    def _generate_scan_id(self) -> str:
        """生成扫描ID"""
        self._scan_counter += 1
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"ASYNC-SCAN-{timestamp}-{self._scan_counter:06d}"
