"""
内容检测引擎模块

提供多维度内容检测能力，包括敏感信息、恶意内容、合规风险等检测。
"""

import re
import hashlib
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any, Set
from datetime import datetime
import json


class DetectionType(Enum):
    """检测类型枚举"""
    PII = auto()              # 个人身份信息
    SENSITIVE_DATA = auto()   # 敏感数据
    INAPPROPRIATE = auto()    # 不当内容
    MALICIOUS = auto()        # 恶意内容
    COMPLIANCE = auto()       # 合规风险
    CUSTOM = auto()           # 自定义规则


class RiskLevel(Enum):
    """风险等级枚举"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class DetectionMatch:
    """检测结果匹配项"""
    type: DetectionType
    risk_level: RiskLevel
    matched_text: str
    position: tuple[int, int]
    confidence: float
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """检测结果数据类"""
    content_id: str
    timestamp: datetime
    matches: List[DetectionMatch]
    overall_risk: RiskLevel
    processing_time_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "content_id": self.content_id,
            "timestamp": self.timestamp.isoformat(),
            "matches": [
                {
                    "type": m.type.name,
                    "risk_level": m.risk_level.name,
                    "matched_text": m.matched_text,
                    "position": m.position,
                    "confidence": m.confidence,
                    "description": m.description,
                    "metadata": m.metadata,
                }
                for m in self.matches
            ],
            "overall_risk": self.overall_risk.name,
            "processing_time_ms": self.processing_time_ms,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class DetectionPattern:
    """检测模式基类"""

    def __init__(
        self,
        name: str,
        detection_type: DetectionType,
        risk_level: RiskLevel,
        description: str = "",
    ):
        self.name = name
        self.detection_type = detection_type
        self.risk_level = risk_level
        self.description = description

    def detect(self, content: str) -> List[DetectionMatch]:
        """检测内容，返回匹配列表"""
        raise NotImplementedError


class RegexPattern(DetectionPattern):
    """正则表达式检测模式"""

    def __init__(
        self,
        name: str,
        pattern: str,
        detection_type: DetectionType,
        risk_level: RiskLevel,
        description: str = "",
        flags: int = 0,
    ):
        super().__init__(name, detection_type, risk_level, description)
        self.regex = re.compile(pattern, flags)

    def detect(self, content: str) -> List[DetectionMatch]:
        matches = []
        for match in self.regex.finditer(content):
            matches.append(
                DetectionMatch(
                    type=self.detection_type,
                    risk_level=self.risk_level,
                    matched_text=match.group(),
                    position=(match.start(), match.end()),
                    confidence=1.0,
                    description=self.description,
                )
            )
        return matches


class KeywordPattern(DetectionPattern):
    """关键词检测模式"""

    def __init__(
        self,
        name: str,
        keywords: List[str],
        detection_type: DetectionType,
        risk_level: RiskLevel,
        description: str = "",
        case_sensitive: bool = False,
    ):
        super().__init__(name, detection_type, risk_level, description)
        self.keywords = keywords
        self.case_sensitive = case_sensitive

    def detect(self, content: str) -> List[DetectionMatch]:
        matches = []
        check_content = content if self.case_sensitive else content.lower()

        for keyword in self.keywords:
            check_keyword = keyword if self.case_sensitive else keyword.lower()
            start = 0
            while True:
                pos = check_content.find(check_keyword, start)
                if pos == -1:
                    break
                matches.append(
                    DetectionMatch(
                        type=self.detection_type,
                        risk_level=self.risk_level,
                        matched_text=content[pos : pos + len(keyword)],
                        position=(pos, pos + len(keyword)),
                        confidence=0.9,
                        description=f"匹配关键词: {keyword}",
                    )
                )
                start = pos + 1

        return matches


class ContentDetector:
    """内容检测引擎"""

    # 预定义检测模式
    DEFAULT_PATTERNS = {
        "phone": RegexPattern(
            name="phone",
            pattern=r"1[3-9]\d{9}",
            detection_type=DetectionType.PII,
            risk_level=RiskLevel.HIGH,
            description="手机号码",
        ),
        "email": RegexPattern(
            name="email",
            pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            detection_type=DetectionType.PII,
            risk_level=RiskLevel.HIGH,
            description="电子邮箱",
        ),
        "id_card": RegexPattern(
            name="id_card",
            pattern=r"\d{17}[\dXx]|\d{15}",
            detection_type=DetectionType.PII,
            risk_level=RiskLevel.CRITICAL,
            description="身份证号码",
        ),
        "bank_card": RegexPattern(
            name="bank_card",
            pattern=r"\d{16,19}",
            detection_type=DetectionType.SENSITIVE_DATA,
            risk_level=RiskLevel.CRITICAL,
            description="银行卡号",
        ),
        "password": KeywordPattern(
            name="password",
            keywords=["password", "密码", "passwd", "pwd", "密钥"],
            detection_type=DetectionType.SENSITIVE_DATA,
            risk_level=RiskLevel.HIGH,
            description="密码相关",
        ),
    }

    def __init__(self, patterns: Optional[Dict[str, DetectionPattern]] = None):
        self.patterns = patterns or self.DEFAULT_PATTERNS.copy()
        self.custom_detectors: List[Callable[[str], List[DetectionMatch]]] = []
        self._stats = {
            "total_scanned": 0,
            "total_matches": 0,
            "scan_history": [],
        }

    def add_pattern(self, name: str, pattern: DetectionPattern) -> None:
        """添加检测模式"""
        self.patterns[name] = pattern

    def remove_pattern(self, name: str) -> bool:
        """移除检测模式"""
        if name in self.patterns:
            del self.patterns[name]
            return True
        return False

    def add_custom_detector(
        self, detector: Callable[[str], List[DetectionMatch]]
    ) -> None:
        """添加自定义检测器"""
        self.custom_detectors.append(detector)

    def detect(
        self,
        content: str,
        content_id: Optional[str] = None,
        detection_types: Optional[Set[DetectionType]] = None,
    ) -> DetectionResult:
        """
        执行内容检测

        Args:
            content: 待检测内容
            content_id: 内容标识符
            detection_types: 指定检测类型，None表示全部

        Returns:
            DetectionResult: 检测结果
        """
        import time

        start_time = time.time()
        content_id = content_id or self._generate_content_id(content)

        all_matches: List[DetectionMatch] = []

        # 执行预定义模式检测
        for pattern in self.patterns.values():
            if detection_types is None or pattern.detection_type in detection_types:
                matches = pattern.detect(content)
                all_matches.extend(matches)

        # 执行自定义检测器
        for detector in self.custom_detectors:
            try:
                matches = detector(content)
                all_matches.extend(matches)
            except Exception as e:
                # 记录错误但不中断检测
                print(f"Custom detector error: {e}")

        # 计算总体风险等级
        overall_risk = self._calculate_overall_risk(all_matches)

        processing_time = (time.time() - start_time) * 1000

        # 更新统计
        self._stats["total_scanned"] += 1
        self._stats["total_matches"] += len(all_matches)

        result = DetectionResult(
            content_id=content_id,
            timestamp=datetime.now(),
            matches=all_matches,
            overall_risk=overall_risk,
            processing_time_ms=processing_time,
        )

        self._stats["scan_history"].append({
            "content_id": content_id,
            "timestamp": result.timestamp.isoformat(),
            "match_count": len(all_matches),
            "risk_level": overall_risk.name,
        })

        return result

    def batch_detect(
        self,
        contents: List[str],
        detection_types: Optional[Set[DetectionType]] = None,
    ) -> List[DetectionResult]:
        """批量检测"""
        results = []
        for i, content in enumerate(contents):
            result = self.detect(content, content_id=f"batch_{i}", detection_types=detection_types)
            results.append(result)
        return results

    def _generate_content_id(self, content: str) -> str:
        """生成内容ID"""
        return hashlib.md5(content.encode()).hexdigest()[:16]

    def _calculate_overall_risk(self, matches: List[DetectionMatch]) -> RiskLevel:
        """计算总体风险等级"""
        if not matches:
            return RiskLevel.LOW

        max_risk = max(matches, key=lambda m: m.risk_level.value).risk_level
        return max_risk

    def get_stats(self) -> Dict[str, Any]:
        """获取检测统计信息"""
        return self._stats.copy()

    def clear_stats(self) -> None:
        """清除统计信息"""
        self._stats = {
            "total_scanned": 0,
            "total_matches": 0,
            "scan_history": [],
        }
