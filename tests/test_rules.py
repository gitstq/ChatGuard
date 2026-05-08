"""
规则引擎测试
"""

import unittest
import json
import tempfile
from pathlib import Path

from chatguard.rules import (
    RuleEngine,
    Rule,
    RuleAction,
    RuleCondition,
    RuleOperator,
    RuleExecutionResult,
)


class TestRuleAction(unittest.TestCase):
    """测试规则动作枚举"""

    def test_action_values(self):
        """测试动作值"""
        self.assertEqual(RuleAction.ALLOW.value, "allow")
        self.assertEqual(RuleAction.BLOCK.value, "block")
        self.assertEqual(RuleAction.FLAG.value, "flag")
        self.assertEqual(RuleAction.MASK.value, "mask")
        self.assertEqual(RuleAction.NOTIFY.value, "notify")
        self.assertEqual(RuleAction.LOG.value, "log")


class TestRuleOperator(unittest.TestCase):
    """测试规则操作符枚举"""

    def test_operator_values(self):
        """测试操作符值"""
        self.assertEqual(RuleOperator.EQUALS.value, "equals")
        self.assertEqual(RuleOperator.CONTAINS.value, "contains")
        self.assertEqual(RuleOperator.MATCHES.value, "matches")


class TestRuleCondition(unittest.TestCase):
    """测试规则条件"""

    def test_equals_condition(self):
        """测试等于条件"""
        condition = RuleCondition(
            field="risk_level",
            operator=RuleOperator.EQUALS,
            value="HIGH",
        )

        context = {"risk_level": "HIGH"}
        self.assertTrue(condition.evaluate(context))

        context = {"risk_level": "LOW"}
        self.assertFalse(condition.evaluate(context))

    def test_contains_condition(self):
        """测试包含条件"""
        condition = RuleCondition(
            field="content",
            operator=RuleOperator.CONTAINS,
            value="敏感词",
        )

        context = {"content": "包含敏感词的内容"}
        self.assertTrue(condition.evaluate(context))

        context = {"content": "正常内容"}
        self.assertFalse(condition.evaluate(context))

    def test_matches_condition(self):
        """测试正则匹配条件"""
        condition = RuleCondition(
            field="email",
            operator=RuleOperator.MATCHES,
            value=r"[\w\.-]+@[\w\.-]+",
        )

        context = {"email": "test@example.com"}
        self.assertTrue(condition.evaluate(context))

        context = {"email": "invalid"}
        self.assertFalse(condition.evaluate(context))

    def test_greater_than_condition(self):
        """测试大于条件"""
        condition = RuleCondition(
            field="score",
            operator=RuleOperator.GREATER_THAN,
            value=50,
        )

        context = {"score": 75}
        self.assertTrue(condition.evaluate(context))

        context = {"score": 30}
        self.assertFalse(condition.evaluate(context))

    def test_in_condition(self):
        """测试包含于条件"""
        condition = RuleCondition(
            field="type",
            operator=RuleOperator.IN,
            value=["PII", "SENSITIVE"],
        )

        context = {"type": "PII"}
        self.assertTrue(condition.evaluate(context))

        context = {"type": "NORMAL"}
        self.assertFalse(condition.evaluate(context))

    def test_exists_condition(self):
        """测试存在条件"""
        condition = RuleCondition(
            field="user_id",
            operator=RuleOperator.EXISTS,
        )

        context = {"user_id": "123"}
        self.assertTrue(condition.evaluate(context))

        context = {}
        self.assertFalse(condition.evaluate(context))

    def test_nested_field(self):
        """测试嵌套字段"""
        condition = RuleCondition(
            field="user.name",
            operator=RuleOperator.EQUALS,
            value="test",
        )

        context = {"user": {"name": "test"}}
        self.assertTrue(condition.evaluate(context))

        context = {"user": {"name": "other"}}
        self.assertFalse(condition.evaluate(context))

    def test_case_insensitive(self):
        """测试不区分大小写"""
        condition = RuleCondition(
            field="text",
            operator=RuleOperator.EQUALS,
            value="TEST",
            case_sensitive=False,
        )

        context = {"text": "test"}
        self.assertTrue(condition.evaluate(context))

    def test_to_dict(self):
        """测试转换为字典"""
        condition = RuleCondition(
            field="test",
            operator=RuleOperator.EQUALS,
            value="value",
        )

        data = condition.to_dict()
        self.assertEqual(data["field"], "test")
        self.assertEqual(data["operator"], "equals")
        self.assertEqual(data["value"], "value")

    def test_from_dict(self):
        """测试从字典创建"""
        data = {
            "field": "test",
            "operator": "equals",
            "value": "value",
            "case_sensitive": True,
        }

        condition = RuleCondition.from_dict(data)
        self.assertEqual(condition.field, "test")
        self.assertEqual(condition.operator, RuleOperator.EQUALS)


class TestRule(unittest.TestCase):
    """测试规则"""

    def test_rule_creation(self):
        """测试规则创建"""
        rule = Rule(
            id="test-rule",
            name="测试规则",
            description="这是一个测试规则",
            conditions=[],
            action=RuleAction.ALLOW,
        )

        self.assertEqual(rule.id, "test-rule")
        self.assertEqual(rule.name, "测试规则")
        self.assertTrue(rule.enabled)

    def test_rule_evaluate_all_mode(self):
        """测试规则评估（全部匹配模式）"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[
                RuleCondition("field1", RuleOperator.EQUALS, "value1"),
                RuleCondition("field2", RuleOperator.EQUALS, "value2"),
            ],
            action=RuleAction.BLOCK,
            match_mode="all",
        )

        context = {"field1": "value1", "field2": "value2"}
        self.assertTrue(rule.evaluate(context))

        context = {"field1": "value1", "field2": "other"}
        self.assertFalse(rule.evaluate(context))

    def test_rule_evaluate_any_mode(self):
        """测试规则评估（任意匹配模式）"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[
                RuleCondition("field1", RuleOperator.EQUALS, "value1"),
                RuleCondition("field2", RuleOperator.EQUALS, "value2"),
            ],
            action=RuleAction.BLOCK,
            match_mode="any",
        )

        context = {"field1": "value1", "field2": "other"}
        self.assertTrue(rule.evaluate(context))

        context = {"field1": "other1", "field2": "other2"}
        self.assertFalse(rule.evaluate(context))

    def test_disabled_rule(self):
        """测试禁用规则"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[],
            action=RuleAction.BLOCK,
            enabled=False,
        )

        context = {}
        self.assertFalse(rule.evaluate(context))

    def test_empty_conditions(self):
        """测试空条件规则"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[],
            action=RuleAction.ALLOW,
        )

        context = {}
        self.assertTrue(rule.evaluate(context))

    def test_to_dict(self):
        """测试转换为字典"""
        rule = Rule(
            id="test",
            name="测试规则",
            description="描述",
            conditions=[RuleCondition("field", RuleOperator.EQUALS, "value")],
            action=RuleAction.BLOCK,
            priority=10,
        )

        data = rule.to_dict()
        self.assertEqual(data["id"], "test")
        self.assertEqual(data["action"], "block")
        self.assertEqual(data["priority"], 10)

    def test_from_dict(self):
        """测试从字典创建"""
        data = {
            "id": "test",
            "name": "测试规则",
            "description": "描述",
            "conditions": [
                {"field": "field1", "operator": "equals", "value": "value1"},
            ],
            "action": "block",
            "priority": 10,
            "enabled": True,
            "tags": ["tag1"],
            "created_at": "2024-01-01T00:00:00",
            "match_mode": "all",
        }

        rule = Rule.from_dict(data)
        self.assertEqual(rule.id, "test")
        self.assertEqual(rule.action, RuleAction.BLOCK)
        self.assertEqual(len(rule.conditions), 1)


class TestRuleEngine(unittest.TestCase):
    """测试规则引擎"""

    def setUp(self):
        self.engine = RuleEngine()

    def test_add_rule(self):
        """测试添加规则"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[],
            action=RuleAction.ALLOW,
        )

        self.engine.add_rule(rule)
        retrieved = self.engine.get_rule("test")
        self.assertEqual(retrieved.id, "test")

    def test_remove_rule(self):
        """测试移除规则"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[],
            action=RuleAction.ALLOW,
        )

        self.engine.add_rule(rule)
        result = self.engine.remove_rule("test")
        self.assertTrue(result)

        result = self.engine.remove_rule("nonexistent")
        self.assertFalse(result)

    def test_list_rules(self):
        """测试列出规则"""
        rule1 = Rule("rule1", "规则1", "", [], RuleAction.ALLOW, priority=10)
        rule2 = Rule("rule2", "规则2", "", [], RuleAction.BLOCK, priority=5, enabled=False)

        self.engine.add_rule(rule1)
        self.engine.add_rule(rule2)

        all_rules = self.engine.list_rules()
        self.assertEqual(len(all_rules), 2)

        enabled_rules = self.engine.list_rules(enabled_only=True)
        self.assertEqual(len(enabled_rules), 1)

    def test_execute_single_match(self):
        """测试执行单条匹配"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[RuleCondition("risk", RuleOperator.EQUALS, "high")],
            action=RuleAction.BLOCK,
        )

        self.engine.add_rule(rule)

        context = {"risk": "high"}
        results = self.engine.execute(context, stop_on_first_match=True)

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)
        self.assertEqual(results[0].action, RuleAction.BLOCK)

    def test_execute_no_match(self):
        """测试执行无匹配"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[RuleCondition("risk", RuleOperator.EQUALS, "high")],
            action=RuleAction.BLOCK,
        )

        self.engine.add_rule(rule)

        context = {"risk": "low"}
        results = self.engine.execute(context)

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].matched)
        self.assertIsNone(results[0].action)

    def test_execute_multiple_rules(self):
        """测试执行多条规则"""
        rule1 = Rule(
            id="rule1",
            name="规则1",
            description="",
            conditions=[RuleCondition("type", RuleOperator.EQUALS, "A")],
            action=RuleAction.ALLOW,
            priority=10,
        )
        rule2 = Rule(
            id="rule2",
            name="规则2",
            description="",
            conditions=[RuleCondition("type", RuleOperator.EQUALS, "B")],
            action=RuleAction.BLOCK,
            priority=5,
        )

        self.engine.add_rule(rule1)
        self.engine.add_rule(rule2)

        context = {"type": "B"}
        results = self.engine.execute(context, stop_on_first_match=False)

        self.assertEqual(len(results), 2)

    def test_execute_action(self):
        """测试执行动作"""
        context = {"content": "test"}
        result = self.engine.execute_action(RuleAction.ALLOW, context, {})

        self.assertTrue(result["allowed"])

    def test_execute_block_action(self):
        """测试执行阻止动作"""
        context = {"content": "test"}
        result = self.engine.execute_action(
            RuleAction.BLOCK,
            context,
            {"message": "Blocked", "reason": "Test"}
        )

        self.assertFalse(result["allowed"])
        self.assertEqual(result["message"], "Blocked")

    def test_custom_action_handler(self):
        """测试自定义动作处理器"""
        def custom_handler(context, params):
            return {"custom": True, "data": params.get("data")}

        self.engine.register_action_handler(RuleAction.CUSTOM, custom_handler)

        context = {}
        result = self.engine.execute_action(RuleAction.CUSTOM, context, {"data": "test"})

        self.assertTrue(result["custom"])
        self.assertEqual(result["data"], "test")

    def test_execution_history(self):
        """测试执行历史"""
        rule = Rule(
            id="test",
            name="测试",
            description="",
            conditions=[],
            action=RuleAction.ALLOW,
        )

        self.engine.add_rule(rule)
        self.engine.execute({})

        history = self.engine.get_execution_history()
        self.assertEqual(len(history), 1)

    def test_clear_history(self):
        """测试清除历史"""
        rule = Rule("test", "测试", "", [], RuleAction.ALLOW)
        self.engine.add_rule(rule)
        self.engine.execute({})

        self.engine.clear_history()
        history = self.engine.get_execution_history()
        self.assertEqual(len(history), 0)

    def test_save_and_load(self):
        """测试保存和加载"""
        rule = Rule(
            id="test",
            name="测试规则",
            description="描述",
            conditions=[RuleCondition("field", RuleOperator.EQUALS, "value")],
            action=RuleAction.BLOCK,
            tags=["test"],
        )

        self.engine.add_rule(rule)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            self.engine.save_to_file(temp_path)

            new_engine = RuleEngine()
            new_engine.load_from_file(temp_path)

            loaded_rule = new_engine.get_rule("test")
            self.assertIsNotNone(loaded_rule)
            self.assertEqual(loaded_rule.name, "测试规则")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_create_default_rules(self):
        """测试创建默认规则"""
        rules = self.engine.create_default_rules()

        self.assertGreater(len(rules), 0)

        for rule in rules:
            retrieved = self.engine.get_rule(rule.id)
            self.assertIsNotNone(retrieved)


class TestRuleExecutionResult(unittest.TestCase):
    """测试规则执行结果"""

    def test_result_creation(self):
        """测试结果创建"""
        result = RuleExecutionResult(
            rule_id="rule1",
            rule_name="规则1",
            matched=True,
            action=RuleAction.BLOCK,
            execution_time_ms=5.0,
        )

        self.assertEqual(result.rule_id, "rule1")
        self.assertTrue(result.matched)


if __name__ == "__main__":
    unittest.main()
