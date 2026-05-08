"""
ChatGuard - AI对话内容安全检测与合规管理系统

一个用于检测、审计和管理AI对话内容的Python库，支持敏感信息检测、合规规则执行和审计日志记录。
"""

__version__ = "1.0.0"
__author__ = "ChatGuard Team"
__license__ = "MIT"

from .detector import ContentDetector, DetectionResult, DetectionType
from .scanner import ContentScanner, ScanResult
from .rules import RuleEngine, Rule, RuleAction, RuleCondition
from .audit import AuditLogger, AuditEntry, AuditLevel
from .reporter import ComplianceReporter, ReportFormat

__all__ = [
    "ContentDetector",
    "DetectionResult",
    "DetectionType",
    "ContentScanner",
    "ScanResult",
    "RuleEngine",
    "Rule",
    "RuleAction",
    "RuleCondition",
    "AuditLogger",
    "AuditEntry",
    "AuditLevel",
    "ComplianceReporter",
    "ReportFormat",
]
