"""
扫描器测试
"""

import unittest
import time
import threading
from datetime import datetime

from chatguard.scanner import (
    ContentScanner,
    AsyncContentScanner,
    ScanResult,
    ScanStatus,
    ScanQueue,
)
from chatguard.detector import ContentDetector, DetectionType, RiskLevel


class TestScanQueue(unittest.TestCase):
    """测试扫描队列"""

    def setUp(self):
        self.queue = ScanQueue(max_size=10)

    def test_submit_and_get(self):
        """测试提交和获取任务"""
        scan_result = ScanResult(
            scan_id="test1",
            content="测试内容",
            status=ScanStatus.PENDING,
        )

        result = self.queue.submit(scan_result)
        self.assertTrue(result)

        retrieved = self.queue.get(timeout=1.0)
        self.assertEqual(retrieved.scan_id, "test1")

    def test_queue_full(self):
        """测试队列满的情况"""
        queue = ScanQueue(max_size=2)

        for i in range(3):
            scan_result = ScanResult(
                scan_id=f"test{i}",
                content="测试",
                status=ScanStatus.PENDING,
            )
            result = queue.submit(scan_result)
            if i < 2:
                self.assertTrue(result)
            else:
                self.assertFalse(result)

    def test_queue_stats(self):
        """测试队列统计"""
        scan_result = ScanResult(
            scan_id="test",
            content="测试",
            status=ScanStatus.PENDING,
        )

        self.queue.submit(scan_result)
        self.queue.mark_processed(success=True)

        stats = self.queue.get_stats()
        self.assertEqual(stats["submitted"], 1)
        self.assertEqual(stats["processed"], 1)


class TestScanResult(unittest.TestCase):
    """测试扫描结果"""

    def test_scan_result_creation(self):
        """测试扫描结果创建"""
        result = ScanResult(
            scan_id="scan123",
            content="测试内容",
            status=ScanStatus.PENDING,
        )

        self.assertEqual(result.scan_id, "scan123")
        self.assertEqual(result.status, ScanStatus.PENDING)

    def test_scan_result_duration(self):
        """测试扫描耗时计算"""
        result = ScanResult(
            scan_id="scan123",
            content="测试",
            status=ScanStatus.COMPLETED,
        )
        time.sleep(0.01)
        result.completed_at = datetime.now()

        self.assertIsNotNone(result.duration_ms)
        self.assertGreater(result.duration_ms, 0)

    def test_scan_result_to_dict(self):
        """测试结果转换为字典"""
        result = ScanResult(
            scan_id="scan123",
            content="测试内容",
            status=ScanStatus.COMPLETED,
        )

        data = result.to_dict()
        self.assertIn("scan_id", data)
        self.assertIn("status", data)


class TestContentScanner(unittest.TestCase):
    """测试内容扫描器"""

    def setUp(self):
        self.scanner = ContentScanner(max_workers=2)

    def tearDown(self):
        self.scanner.stop(wait=False)

    def test_scan_sync(self):
        """测试同步扫描"""
        result = self.scanner.scan("手机号: 13800138000", blocking=True)

        self.assertEqual(result.status, ScanStatus.COMPLETED)
        self.assertIsNotNone(result.detection_result)
        self.assertEqual(len(result.detection_result.matches), 1)

    def test_scan_no_sensitive(self):
        """测试扫描无敏感内容"""
        result = self.scanner.scan("这是一段普通文本", blocking=True)

        self.assertEqual(result.status, ScanStatus.COMPLETED)
        self.assertEqual(len(result.detection_result.matches), 0)

    def test_batch_scan(self):
        """测试批量扫描"""
        contents = [
            "手机号: 13800138000",
            "普通文本",
            "邮箱: test@example.com",
        ]
        results = self.scanner.batch_scan(contents)

        self.assertEqual(len(results), 3)
        for result in results:
            self.assertEqual(result.status, ScanStatus.COMPLETED)

    def test_scan_with_metadata(self):
        """测试带元数据的扫描"""
        metadata = {"user_id": "user123", "source": "api"}
        result = self.scanner.scan("测试", metadata=metadata, blocking=True)

        self.assertEqual(result.metadata, metadata)

    def test_scan_id_generation(self):
        """测试扫描ID生成"""
        result1 = self.scanner.scan("测试1", blocking=True)
        result2 = self.scanner.scan("测试2", blocking=True)

        self.assertNotEqual(result1.scan_id, result2.scan_id)
        self.assertTrue(result1.scan_id.startswith("SCAN-"))

    def test_callback(self):
        """测试回调函数"""
        callback_results = []

        def callback(result):
            callback_results.append(result.scan_id)

        self.scanner.add_callback(callback)
        result = self.scanner.scan("测试", blocking=True)

        self.assertEqual(len(callback_results), 1)
        self.assertEqual(callback_results[0], result.scan_id)

        # 测试移除回调
        self.scanner.remove_callback(callback)
        callback_results.clear()
        self.scanner.scan("测试2", blocking=True)
        self.assertEqual(len(callback_results), 0)

    def test_scanner_stats(self):
        """测试扫描器统计"""
        self.scanner.scan("测试", blocking=True)
        stats = self.scanner.get_stats()

        self.assertIn("running", stats)
        self.assertIn("workers", stats)
        self.assertIn("queue_size", stats)


class TestAsyncContentScanner(unittest.TestCase):
    """测试异步内容扫描器"""

    def setUp(self):
        self.scanner = AsyncContentScanner()

    def test_async_scan(self):
        """测试异步扫描"""
        import asyncio

        async def run_test():
            result = await self.scanner.scan("手机号: 13800138000")
            self.assertEqual(result.status, ScanStatus.COMPLETED)
            self.assertEqual(len(result.detection_result.matches), 1)

        asyncio.run(run_test())

    def test_async_batch_scan(self):
        """测试异步批量扫描"""
        import asyncio

        async def run_test():
            contents = [
                "手机号: 13800138000",
                "普通文本",
                "邮箱: test@example.com",
            ]
            results = await self.scanner.batch_scan(contents)

            self.assertEqual(len(results), 3)
            for result in results:
                self.assertEqual(result.status, ScanStatus.COMPLETED)

        asyncio.run(run_test())


class TestScanStatus(unittest.TestCase):
    """测试扫描状态枚举"""

    def test_status_values(self):
        """测试状态值"""
        self.assertIsNotNone(ScanStatus.PENDING)
        self.assertIsNotNone(ScanStatus.SCANNING)
        self.assertIsNotNone(ScanStatus.COMPLETED)
        self.assertIsNotNone(ScanStatus.FAILED)
        self.assertIsNotNone(ScanStatus.CANCELLED)


if __name__ == "__main__":
    unittest.main()
