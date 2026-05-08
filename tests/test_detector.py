"""
内容检测引擎测试
"""

import unittest
from datetime import datetime

from chatguard.detector import (
    ContentDetector,
    DetectionResult,
    DetectionMatch,
    DetectionType,
    RiskLevel,
    RegexPattern,
    KeywordPattern,
)


class TestDetectionTypes(unittest.TestCase):
    """测试检测类型枚举"""

    def test_detection_type_values(self):
        """测试检测类型枚举值"""
        self.assertIsNotNone(DetectionType.PII)
        self.assertIsNotNone(DetectionType.SENSITIVE_DATA)
        self.assertIsNotNone(DetectionType.INAPPROPRIATE)
        self.assertIsNotNone(DetectionType.MALICIOUS)
        self.assertIsNotNone(DetectionType.COMPLIANCE)
        self.assertIsNotNone(DetectionType.CUSTOM)


class TestRiskLevel(unittest.TestCase):
    """测试风险等级枚举"""

    def test_risk_level_ordering(self):
        """测试风险等级排序"""
        self.assertLess(RiskLevel.LOW.value, RiskLevel.MEDIUM.value)
        self.assertLess(RiskLevel.MEDIUM.value, RiskLevel.HIGH.value)
        self.assertLess(RiskLevel.HIGH.value, RiskLevel.CRITICAL.value)


class TestRegexPattern(unittest.TestCase):
    """测试正则表达式检测模式"""

    def setUp(self):
        self.pattern = RegexPattern(
            name="test_phone",
            pattern=r"1[3-9]\d{9}",
            detection_type=DetectionType.PII,
            risk_level=RiskLevel.HIGH,
            description="测试手机号",
        )

    def test_detect_phone_number(self):
        """测试检测手机号"""
        content = "我的手机号是13800138000"
        matches = self.pattern.detect(content)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].matched_text, "13800138000")
        self.assertEqual(matches[0].type, DetectionType.PII)
        self.assertEqual(matches[0].risk_level, RiskLevel.HIGH)

    def test_detect_multiple_phones(self):
        """测试检测多个手机号"""
        content = "联系方式: 13800138000 或 13900139000"
        matches = self.pattern.detect(content)

        self.assertEqual(len(matches), 2)

    def test_no_match(self):
        """测试无匹配情况"""
        content = "这是一段普通文本"
        matches = self.pattern.detect(content)

        self.assertEqual(len(matches), 0)


class TestKeywordPattern(unittest.TestCase):
    """测试关键词检测模式"""

    def setUp(self):
        self.pattern = KeywordPattern(
            name="test_keywords",
            keywords=["密码", "password", "密钥"],
            detection_type=DetectionType.SENSITIVE_DATA,
            risk_level=RiskLevel.HIGH,
            description="敏感关键词",
        )

    def test_detect_keyword(self):
        """测试检测关键词"""
        content = "请设置您的密码"
        matches = self.pattern.detect(content)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].matched_text, "密码")

    def test_case_insensitive(self):
        """测试不区分大小写"""
        pattern = KeywordPattern(
            name="test",
            keywords=["password"],
            detection_type=DetectionType.SENSITIVE_DATA,
            risk_level=RiskLevel.HIGH,
            case_sensitive=False,
        )
        content = "请输入PASSWORD"
        matches = pattern.detect(content)

        self.assertEqual(len(matches), 1)


class TestContentDetector(unittest.TestCase):
    """测试内容检测引擎"""

    def setUp(self):
        self.detector = ContentDetector()

    def test_detect_phone(self):
        """测试检测手机号"""
        content = "联系电话: 13800138000"
        result = self.detector.detect(content)

        self.assertIsInstance(result, DetectionResult)
        self.assertEqual(len(result.matches), 1)
        self.assertEqual(result.matches[0].matched_text, "13800138000")

    def test_detect_email(self):
        """测试检测邮箱"""
        content = "邮箱地址: test@example.com"
        result = self.detector.detect(content)

        email_matches = [m for m in result.matches if m.type == DetectionType.PII]
        self.assertTrue(len(email_matches) > 0)

    def test_detect_id_card(self):
        """测试检测身份证号"""
        content = "身份证号: 110101199001011234"
        result = self.detector.detect(content)

        self.assertEqual(result.overall_risk, RiskLevel.CRITICAL)

    def test_no_sensitive_content(self):
        """测试无敏感内容"""
        content = "这是一段完全普通的文本内容"
        result = self.detector.detect(content)

        self.assertEqual(len(result.matches), 0)
        self.assertEqual(result.overall_risk, RiskLevel.LOW)

    def test_content_id_generation(self):
        """测试内容ID生成"""
        content = "测试内容"
        result = self.detector.detect(content)

        self.assertIsNotNone(result.content_id)
        self.assertEqual(len(result.content_id), 16)

    def test_batch_detect(self):
        """测试批量检测"""
        contents = [
            "手机号: 13800138000",
            "邮箱: test@example.com",
            "普通文本",
        ]
        results = self.detector.batch_detect(contents)

        self.assertEqual(len(results), 3)
        self.assertEqual(len(results[0].matches), 1)  # 手机号
        self.assertTrue(len(results[1].matches) > 0)  # 邮箱
        self.assertEqual(len(results[2].matches), 0)  # 普通文本

    def test_add_custom_pattern(self):
        """测试添加自定义模式"""
        custom_pattern = RegexPattern(
            name="custom",
            pattern=r"\d{4}-\d{4}-\d{4}-\d{4}",
            detection_type=DetectionType.CUSTOM,
            risk_level=RiskLevel.MEDIUM,
        )
        self.detector.add_pattern("custom", custom_pattern)

        content = "卡号: 1234-5678-9012-3456"
        result = self.detector.detect(content)

        custom_matches = [m for m in result.matches if m.type == DetectionType.CUSTOM]
        self.assertEqual(len(custom_matches), 1)

    def test_remove_pattern(self):
        """测试移除模式"""
        result = self.detector.remove_pattern("phone")
        self.assertTrue(result)

        content = "手机号: 13800138000"
        result = self.detector.detect(content)

        phone_matches = [m for m in result.matches if "13800138000" in m.matched_text]
        self.assertEqual(len(phone_matches), 0)

    def test_detection_result_to_dict(self):
        """测试结果转换为字典"""
        content = "测试"
        result = self.detector.detect(content)
        data = result.to_dict()

        self.assertIn("content_id", data)
        self.assertIn("timestamp", data)
        self.assertIn("matches", data)
        self.assertIn("overall_risk", data)

    def test_detection_result_to_json(self):
        """测试结果转换为JSON"""
        content = "测试"
        result = self.detector.detect(content)
        json_str = result.to_json()

        self.assertIsInstance(json_str, str)
        self.assertIn("content_id", json_str)

    def test_stats(self):
        """测试统计信息"""
        self.detector.detect("内容1")
        self.detector.detect("内容2")

        stats = self.detector.get_stats()

        self.assertEqual(stats["total_scanned"], 2)
        self.assertIn("scan_history", stats)

    def test_clear_stats(self):
        """测试清除统计"""
        self.detector.detect("内容")
        self.detector.clear_stats()

        stats = self.detector.get_stats()
        self.assertEqual(stats["total_scanned"], 0)


class TestDetectionResult(unittest.TestCase):
    """测试检测结果数据类"""

    def test_result_creation(self):
        """测试结果创建"""
        match = DetectionMatch(
            type=DetectionType.PII,
            risk_level=RiskLevel.HIGH,
            matched_text="test",
            position=(0, 4),
            confidence=0.9,
            description="测试",
        )
        result = DetectionResult(
            content_id="test123",
            timestamp=datetime.now(),
            matches=[match],
            overall_risk=RiskLevel.HIGH,
            processing_time_ms=10.0,
        )

        self.assertEqual(result.content_id, "test123")
        self.assertEqual(len(result.matches), 1)


if __name__ == "__main__":
    unittest.main()
