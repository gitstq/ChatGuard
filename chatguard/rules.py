"""
规则引擎模块

提供灵活的规则定义、管理和执行能力，支持复杂的合规策略。
"""

import re
import json
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any, Union, Set
from datetime import datetime
from pathlib import Path


class RuleAction(Enum):
    """规则动作枚举"""
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"
    MASK = "mask"
    NOTIFY = "notify"
    LOG = "log"
    CUSTOM = "custom"


class RuleOperator(Enum):
    """规则操作符枚举"""
    EQUALS = "equals"
    CONTAINS = "contains"
    MATCHES = "matches"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


@dataclass
class RuleCondition:
    """规则条件"""
    field: str
    operator: RuleOperator
    value: Any = None
    case_sensitive: bool = True

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """评估条件"""
        field_value = self._get_field_value(context)

        if self.operator == RuleOperator.EXISTS:
            return field_value is not None
        if self.operator == RuleOperator.NOT_EXISTS:
            return field_value is None

        if field_value is None:
            return False

        if self.operator == RuleOperator.EQUALS:
            return self._equals(field_value, self.value)
        elif self.operator == RuleOperator.CONTAINS:
            return self._contains(field_value, self.value)
        elif self.operator == RuleOperator.MATCHES:
            return self._matches(field_value, self.value)
        elif self.operator == RuleOperator.GREATER_THAN:
            return field_value > self.value
        elif self.operator == RuleOperator.LESS_THAN:
            return field_value < self.value
        elif self.operator == RuleOperator.IN:
            return field_value in self.value
        elif self.operator == RuleOperator.NOT_IN:
            return field_value not in self.value

        return False

    def _get_field_value(self, context: Dict[str, Any]) -> Any:
        """获取字段值，支持嵌套路径"""
        keys = self.field.split(".")
        value = context
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value

    def _equals(self, a: Any, b: Any) -> bool:
        """相等比较"""
        if not self.case_sensitive and isinstance(a, str) and isinstance(b, str):
            return a.lower() == b.lower()
        return a == b

    def _contains(self, a: Any, b: Any) -> bool:
        """包含比较"""
        if isinstance(a, str) and isinstance(b, str):
            if not self.case_sensitive:
                return b.lower() in a.lower()
            return b in a
        return False

    def _matches(self, a: Any, b: Any) -> bool:
        """正则匹配"""
        if isinstance(a, str) and isinstance(b, str):
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return bool(re.search(b, a, flags))
        return False

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
            "case_sensitive": self.case_sensitive,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleCondition":
        """从字典创建"""
        return cls(
            field=data["field"],
            operator=RuleOperator(data["operator"]),
            value=data.get("value"),
            case_sensitive=data.get("case_sensitive", True),
        )


@dataclass
class Rule:
    """规则定义"""
    id: str
    name: str
    description: str
    conditions: List[RuleCondition]
    action: RuleAction
    action_params: Dict[str, Any] = field(default_factory=dict)
    priority: int = 100
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    match_mode: str = "all"  # "all" 或 "any"

    def evaluate(self, context: Dict[str, Any]) -> bool:
        """评估规则是否匹配"""
        if not self.enabled:
            return False

        if not self.conditions:
            return True

        if self.match_mode == "all":
            return all(cond.evaluate(context) for cond in self.conditions)
        else:  # any
            return any(cond.evaluate(context) for cond in self.conditions)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "conditions": [c.to_dict() for c in self.conditions],
            "action": self.action.value,
            "action_params": self.action_params,
            "priority": self.priority,
            "enabled": self.enabled,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "match_mode": self.match_mode,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        """从字典创建"""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            conditions=[RuleCondition.from_dict(c) for c in data.get("conditions", [])],
            action=RuleAction(data["action"]),
            action_params=data.get("action_params", {}),
            priority=data.get("priority", 100),
            enabled=data.get("enabled", True),
            tags=data.get("tags", []),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            match_mode=data.get("match_mode", "all"),
        )


@dataclass
class RuleExecutionResult:
    """规则执行结果"""
    rule_id: str
    rule_name: str
    matched: bool
    action: Optional[RuleAction] = None
    action_params: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


class RuleEngine:
    """规则引擎"""

    def __init__(self):
        self._rules: Dict[str, Rule] = {}
        self._action_handlers: Dict[RuleAction, Callable[[Dict[str, Any], Dict[str, Any]], Any]] = {}
        self._execution_history: List[RuleExecutionResult] = []
        self._max_history_size = 10000

        # 注册默认动作处理器
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """注册默认动作处理器"""
        self._action_handlers[RuleAction.ALLOW] = self._handle_allow
        self._action_handlers[RuleAction.BLOCK] = self._handle_block
        self._action_handlers[RuleAction.FLAG] = self._handle_flag
        self._action_handlers[RuleAction.MASK] = self._handle_mask
        self._action_handlers[RuleAction.NOTIFY] = self._handle_notify
        self._action_handlers[RuleAction.LOG] = self._handle_log

    def _handle_allow(self, context: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """处理允许动作"""
        return {"allowed": True, "message": params.get("message", "Content allowed")}

    def _handle_block(self, context: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """处理阻止动作"""
        return {
            "allowed": False,
            "message": params.get("message", "Content blocked by policy"),
            "reason": params.get("reason", "Policy violation"),
        }

    def _handle_flag(self, context: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """处理标记动作"""
        return {
            "allowed": True,
            "flagged": True,
            "flag_reason": params.get("reason", "Content flagged for review"),
        }

    def _handle_mask(self, context: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """处理脱敏动作"""
        content = context.get("content", "")
        mask_char = params.get("mask_char", "*")
        return {
            "allowed": True,
            "masked": True,
            "masked_content": mask_char * len(content),
        }

    def _handle_notify(self, context: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """处理通知动作"""
        return {
            "allowed": True,
            "notify": True,
            "notify_channels": params.get("channels", ["email"]),
            "notify_message": params.get("message", "Alert triggered"),
        }

    def _handle_log(self, context: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        """处理日志动作"""
        return {
            "allowed": True,
            "logged": True,
            "log_level": params.get("level", "info"),
        }

    def add_rule(self, rule: Rule) -> None:
        """添加规则"""
        self._rules[rule.id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        """移除规则"""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """获取规则"""
        return self._rules.get(rule_id)

    def list_rules(
        self,
        enabled_only: bool = False,
        tags: Optional[Set[str]] = None,
    ) -> List[Rule]:
        """列出规则"""
        rules = list(self._rules.values())

        if enabled_only:
            rules = [r for r in rules if r.enabled]

        if tags:
            rules = [r for r in rules if any(t in r.tags for t in tags)]

        # 按优先级排序
        rules.sort(key=lambda r: r.priority)
        return rules

    def execute(
        self,
        context: Dict[str, Any],
        stop_on_first_match: bool = True,
    ) -> List[RuleExecutionResult]:
        """
        执行规则引擎

        Args:
            context: 执行上下文
            stop_on_first_match: 匹配到第一条规则后是否停止

        Returns:
            List[RuleExecutionResult]: 执行结果列表
        """
        import time

        results = []
        sorted_rules = sorted(self._rules.values(), key=lambda r: r.priority)

        for rule in sorted_rules:
            start_time = time.time()
            matched = rule.evaluate(context)
            execution_time = (time.time() - start_time) * 1000

            result = RuleExecutionResult(
                rule_id=rule.id,
                rule_name=rule.name,
                matched=matched,
                action=rule.action if matched else None,
                action_params=rule.action_params if matched else {},
                execution_time_ms=execution_time,
            )

            results.append(result)
            self._add_to_history(result)

            if matched and stop_on_first_match:
                break

        return results

    def execute_action(
        self,
        action: RuleAction,
        context: Dict[str, Any],
        params: Dict[str, Any],
    ) -> Any:
        """执行特定动作"""
        handler = self._action_handlers.get(action)
        if handler:
            return handler(context, params)
        return None

    def register_action_handler(
        self,
        action: RuleAction,
        handler: Callable[[Dict[str, Any], Dict[str, Any]], Any],
    ) -> None:
        """注册自定义动作处理器"""
        self._action_handlers[action] = handler

    def _add_to_history(self, result: RuleExecutionResult) -> None:
        """添加到执行历史"""
        self._execution_history.append(result)
        if len(self._execution_history) > self._max_history_size:
            self._execution_history = self._execution_history[-self._max_history_size:]

    def get_execution_history(
        self,
        limit: int = 100,
        rule_id: Optional[str] = None,
    ) -> List[RuleExecutionResult]:
        """获取执行历史"""
        history = self._execution_history
        if rule_id:
            history = [h for h in history if h.rule_id == rule_id]
        return history[-limit:]

    def clear_history(self) -> None:
        """清除执行历史"""
        self._execution_history = []

    def load_from_file(self, filepath: Union[str, Path]) -> None:
        """从文件加载规则"""
        path = Path(filepath)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for rule_data in data.get("rules", []):
            rule = Rule.from_dict(rule_data)
            self.add_rule(rule)

    def save_to_file(self, filepath: Union[str, Path]) -> None:
        """保存规则到文件"""
        path = Path(filepath)
        data = {
            "version": "1.0",
            "export_time": datetime.now().isoformat(),
            "rules": [rule.to_dict() for rule in self._rules.values()],
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def create_default_rules(self) -> List[Rule]:
        """创建默认规则集"""
        default_rules = [
            Rule(
                id="block-high-risk-pii",
                name="阻止高风险个人身份信息",
                description="当检测到高风险个人身份信息时阻止内容",
                conditions=[
                    RuleCondition(
                        field="risk_level",
                        operator=RuleOperator.EQUALS,
                        value="CRITICAL",
                    ),
                ],
                action=RuleAction.BLOCK,
                action_params={
                    "message": "检测到敏感个人信息，内容已被阻止",
                    "reason": "Critical PII detected",
                },
                priority=10,
                tags=["pii", "security", "high-priority"],
            ),
            Rule(
                id="flag-inappropriate",
                name="标记不当内容",
                description="标记可能包含不当内容的消息",
                conditions=[
                    RuleCondition(
                        field="detection_type",
                        operator=RuleOperator.EQUALS,
                        value="INAPPROPRIATE",
                    ),
                ],
                action=RuleAction.FLAG,
                action_params={
                    "reason": "Content may be inappropriate",
                },
                priority=50,
                tags=["content", "moderation"],
            ),
            Rule(
                id="log-sensitive",
                name="记录敏感操作",
                description="记录所有包含敏感数据的操作",
                conditions=[
                    RuleCondition(
                        field="detection_type",
                        operator=RuleOperator.IN,
                        value=["PII", "SENSITIVE_DATA"],
                    ),
                ],
                action=RuleAction.LOG,
                action_params={"level": "warning"},
                priority=100,
                tags=["logging", "audit"],
            ),
        ]

        for rule in default_rules:
            self.add_rule(rule)

        return default_rules
