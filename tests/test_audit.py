"""
审计日志系统测试
"""

import unittest
import tempfile
import json
from datetime import datetime, timedelta
from pathlib import Path

from chatguard.audit import (
    AuditLogger,
    AuditEntry,
    AuditLevel,
    AuditEventType,
    FileAuditStorage,
    SQLiteAuditStorage,
)


class TestAuditLevel(unittest.TestCase):
    """测试审计日志级别"""

    def test_level_values(self):
        """测试级别值"""
        self.assertEqual(AuditLevel.DEBUG.value, 10)
        self.assertEqual(AuditLevel.INFO.value, 20)
        self.assertEqual(AuditLevel.WARNING.value, 30)
        self.assertEqual(AuditLevel.ERROR.value, 40)
        self.assertEqual(AuditLevel.CRITICAL.value, 50)

    def test_level_value_names(self):
        """测试级别名称"""
        self.assertEqual(AuditLevel.DEBUG.value_name, "debug")
        self.assertEqual(AuditLevel.INFO.value_name, "info")
        self.assertEqual(AuditLevel.WARNING.value_name, "warning")
        self.assertEqual(AuditLevel.ERROR.value_name, "error")
        self.assertEqual(AuditLevel.CRITICAL.value_name, "critical")


class TestAuditEventType(unittest.TestCase):
    """测试审计事件类型"""

    def test_event_type_values(self):
        """测试事件类型值"""
        self.assertEqual(AuditEventType.CONTENT_SCAN.value, "content_scan")
        self.assertEqual(AuditEventType.RULE_MATCH.value, "rule_match")
        self.assertEqual(AuditEventType.POLICY_VIOLATION.value, "policy_violation")


class TestAuditEntry(unittest.TestCase):
    """测试审计日志条目"""

    def test_entry_creation(self):
        """测试条目创建"""
        entry = AuditEntry(
            id="test-123",
            timestamp=datetime.now(),
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
        )

        self.assertEqual(entry.id, "test-123")
        self.assertEqual(entry.level, AuditLevel.INFO)
        self.assertIsNotNone(entry.hash)

    def test_hash_generation(self):
        """测试哈希生成"""
        entry = AuditEntry(
            id="test-123",
            timestamp=datetime.now(),
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
        )

        self.assertIsNotNone(entry.hash)
        self.assertEqual(len(entry.hash), 64)  # SHA-256哈希长度

    def test_integrity_verification(self):
        """测试完整性验证"""
        entry = AuditEntry(
            id="test-123",
            timestamp=datetime.now(),
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
        )

        self.assertTrue(entry.verify_integrity())

        # 修改内容后验证应失败
        entry.message = "被篡改的消息"
        self.assertFalse(entry.verify_integrity())

    def test_to_dict(self):
        """测试转换为字典"""
        entry = AuditEntry(
            id="test-123",
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
            user_id="user123",
            metadata={"key": "value"},
        )

        data = entry.to_dict()
        self.assertEqual(data["id"], "test-123")
        self.assertEqual(data["level"], "info")
        self.assertEqual(data["user_id"], "user123")
        self.assertEqual(data["metadata"]["key"], "value")

    def test_to_json(self):
        """测试转换为JSON"""
        entry = AuditEntry(
            id="test-123",
            timestamp=datetime.now(),
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
        )

        json_str = entry.to_json()
        self.assertIsInstance(json_str, str)

        # 验证JSON可解析
        data = json.loads(json_str)
        self.assertEqual(data["id"], "test-123")


class TestFileAuditStorage(unittest.TestCase):
    """测试文件存储后端"""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_file.close()
        self.storage = FileAuditStorage(self.temp_file.name)

    def tearDown(self):
        Path(self.temp_file.name).unlink(missing_ok=True)

    def test_write_and_read(self):
        """测试写入和读取"""
        entry = AuditEntry(
            id="test-123",
            timestamp=datetime.now(),
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
        )

        result = self.storage.write(entry)
        self.assertTrue(result)

        entries = self.storage.read()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].id, "test-123")

    def test_read_with_filters(self):
        """测试带过滤条件的读取"""
        # 写入不同级别的日志
        for level in [AuditLevel.INFO, AuditLevel.WARNING, AuditLevel.ERROR]:
            entry = AuditEntry(
                id=f"test-{level.value_name}",
                timestamp=datetime.now(),
                level=level,
                event_type=AuditEventType.CONTENT_SCAN,
                source="test",
                message=f"{level.value_name} message",
            )
            self.storage.write(entry)

        # 按级别过滤
        entries = self.storage.read(level=AuditLevel.WARNING)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].level, AuditLevel.WARNING)

    def test_read_with_time_range(self):
        """测试按时间范围读取"""
        now = datetime.now()
        old_time = now - timedelta(hours=2)

        entry1 = AuditEntry(
            id="old",
            timestamp=old_time,
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="旧消息",
        )
        entry2 = AuditEntry(
            id="new",
            timestamp=now,
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="新消息",
        )

        self.storage.write(entry1)
        self.storage.write(entry2)

        # 读取最近1小时的日志
        entries = self.storage.read(start_time=now - timedelta(hours=1))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].id, "new")


class TestSQLiteAuditStorage(unittest.TestCase):
    """测试SQLite存储后端"""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_file.close()
        self.storage = SQLiteAuditStorage(self.temp_file.name)

    def tearDown(self):
        Path(self.temp_file.name).unlink(missing_ok=True)

    def test_write_and_read(self):
        """测试写入和读取"""
        entry = AuditEntry(
            id="test-123",
            timestamp=datetime.now(),
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
        )

        result = self.storage.write(entry)
        self.assertTrue(result)

        entries = self.storage.read()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].id, "test-123")

    def test_read_with_filters(self):
        """测试带过滤条件的读取"""
        for level in [AuditLevel.INFO, AuditLevel.WARNING, AuditLevel.ERROR]:
            entry = AuditEntry(
                id=f"test-{level.value_name}",
                timestamp=datetime.now(),
                level=level,
                event_type=AuditEventType.CONTENT_SCAN,
                source="test",
                message=f"{level.value_name} message",
            )
            self.storage.write(entry)

        entries = self.storage.read(level=AuditLevel.ERROR)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].level, AuditLevel.ERROR)

    def test_read_with_event_type_filter(self):
        """测试按事件类型过滤"""
        for event_type in [AuditEventType.CONTENT_SCAN, AuditEventType.RULE_MATCH]:
            entry = AuditEntry(
                id=f"test-{event_type.value}",
                timestamp=datetime.now(),
                level=AuditLevel.INFO,
                event_type=event_type,
                source="test",
                message=f"{event_type.value} message",
            )
            self.storage.write(entry)

        entries = self.storage.read(event_type=AuditEventType.RULE_MATCH)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].event_type, AuditEventType.RULE_MATCH)


class TestAuditLogger(unittest.TestCase):
    """测试审计日志记录器"""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_file.close()
        storage = FileAuditStorage(self.temp_file.name)
        self.logger = AuditLogger(storage)
        # 确保每个测试开始时日志级别为DEBUG
        self.logger.set_min_level(AuditLevel.DEBUG)

    def tearDown(self):
        Path(self.temp_file.name).unlink(missing_ok=True)

    def test_log_entry(self):
        """测试记录日志"""
        entry = self.logger.log(
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
        )

        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, AuditLevel.INFO)

    def test_log_with_min_level(self):
        """测试最小日志级别过滤"""
        self.logger.set_min_level(AuditLevel.WARNING)

        # DEBUG级别不应被记录
        entry = self.logger.log(
            level=AuditLevel.DEBUG,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="调试消息",
        )
        self.assertIsNone(entry)

        # WARNING级别应被记录
        entry = self.logger.log(
            level=AuditLevel.WARNING,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="警告消息",
        )
        self.assertIsNotNone(entry)

    def test_convenience_methods(self):
        """测试便捷方法"""
        # 重置最小日志级别为DEBUG
        self.logger.set_min_level(AuditLevel.DEBUG)

        entry = self.logger.info(
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="信息消息",
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, AuditLevel.INFO)

        entry = self.logger.warning(
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="警告消息",
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, AuditLevel.WARNING)

        entry = self.logger.error(
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="错误消息",
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, AuditLevel.ERROR)

        entry = self.logger.critical(
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="严重消息",
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.level, AuditLevel.CRITICAL)

    def test_query(self):
        """测试查询日志"""
        # 记录一些日志
        self.logger.info(AuditEventType.CONTENT_SCAN, "test", "消息1")
        self.logger.warning(AuditEventType.RULE_MATCH, "test", "消息2")

        entries = self.logger.query(limit=10)
        self.assertEqual(len(entries), 2)

    def test_get_recent(self):
        """测试获取最近日志"""
        self.logger.info(AuditEventType.CONTENT_SCAN, "test", "消息")

        entries = self.logger.get_recent(hours=1)
        self.assertEqual(len(entries), 1)

    def test_get_stats(self):
        """测试获取统计信息"""
        self.logger.info(AuditEventType.CONTENT_SCAN, "test", "消息1")
        self.logger.warning(AuditEventType.RULE_MATCH, "test", "消息2")
        self.logger.error(AuditEventType.POLICY_VIOLATION, "test", "消息3")

        stats = self.logger.get_stats(hours=1)
        self.assertEqual(stats["total_entries"], 3)
        self.assertEqual(stats["by_level"]["info"], 1)
        self.assertEqual(stats["by_level"]["warning"], 1)
        self.assertEqual(stats["by_level"]["error"], 1)

    def test_callback(self):
        """测试回调函数"""
        callback_entries = []

        def callback(entry):
            callback_entries.append(entry.id)

        self.logger.add_callback(callback)
        entry = self.logger.info(AuditEventType.CONTENT_SCAN, "test", "消息")

        self.assertEqual(len(callback_entries), 1)
        self.assertEqual(callback_entries[0], entry.id)

        # 测试移除回调
        self.logger.remove_callback(callback)
        self.logger.info(AuditEventType.CONTENT_SCAN, "test", "消息2")
        self.assertEqual(len(callback_entries), 1)

    def test_export_to_file(self):
        """测试导出到文件"""
        self.logger.info(AuditEventType.CONTENT_SCAN, "test", "消息1")
        self.logger.info(AuditEventType.CONTENT_SCAN, "test", "消息2")

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            export_path = f.name

        try:
            count = self.logger.export_to_file(export_path)
            self.assertEqual(count, 2)

            content = Path(export_path).read_text(encoding='utf-8')
            lines = content.strip().split('\n')
            self.assertEqual(len(lines), 2)
        finally:
            Path(export_path).unlink(missing_ok=True)

    def test_log_with_metadata(self):
        """测试带元数据的日志"""
        entry = self.logger.log(
            level=AuditLevel.INFO,
            event_type=AuditEventType.CONTENT_SCAN,
            source="test",
            message="测试消息",
            user_id="user123",
            session_id="session456",
            content_id="content789",
            metadata={"custom_key": "custom_value"},
        )

        self.assertEqual(entry.user_id, "user123")
        self.assertEqual(entry.session_id, "session456")
        self.assertEqual(entry.content_id, "content789")
        self.assertEqual(entry.metadata["custom_key"], "custom_value")


if __name__ == "__main__":
    unittest.main()
