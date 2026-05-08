"""
命令行界面模块

提供ChatGuard的命令行交互界面，支持扫描、检测、规则管理等功能。
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List

from .detector import ContentDetector, DetectionType, RiskLevel
from .scanner import ContentScanner
from .rules import RuleEngine, Rule, RuleAction, RuleCondition, RuleOperator
from .audit import AuditLogger, AuditLevel, AuditEventType, FileAuditStorage, SQLiteAuditStorage
from .reporter import ComplianceReporter, ReportFormat


def create_parser() -> argparse.ArgumentParser:
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="chatguard",
        description="ChatGuard - AI对话内容安全检测与合规管理系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  chatguard scan "需要检测的文本内容"
  chatguard scan -f input.txt -o result.json
  chatguard rules --list
  chatguard audit --query --hours 24
  chatguard report --output report.html --format html
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # scan 命令
    scan_parser = subparsers.add_parser("scan", help="扫描内容")
    scan_parser.add_argument("content", nargs="?", help="要扫描的文本内容")
    scan_parser.add_argument("-f", "--file", help="从文件读取内容")
    scan_parser.add_argument("-o", "--output", help="输出结果到文件")
    scan_parser.add_argument(
        "-t", "--type",
        choices=[t.name for t in DetectionType],
        nargs="+",
        help="指定检测类型"
    )
    scan_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="输出格式"
    )

    # rules 命令
    rules_parser = subparsers.add_parser("rules", help="规则管理")
    rules_parser.add_argument("--list", action="store_true", help="列出所有规则")
    rules_parser.add_argument("--add", help="添加规则（JSON格式）")
    rules_parser.add_argument("--remove", help="移除规则")
    rules_parser.add_argument("--enable", help="启用规则")
    rules_parser.add_argument("--disable", help="禁用规则")
    rules_parser.add_argument("--export", help="导出规则到文件")
    rules_parser.add_argument("--import-file", help="从文件导入规则")
    rules_parser.add_argument("--init-default", action="store_true", help="初始化默认规则")

    # audit 命令
    audit_parser = subparsers.add_parser("audit", help="审计日志")
    audit_parser.add_argument("--query", action="store_true", help="查询日志")
    audit_parser.add_argument("--hours", type=int, default=24, help="查询最近N小时的日志")
    audit_parser.add_argument("--level", choices=[l.value for l in AuditLevel], help="按级别过滤")
    audit_parser.add_argument("--event-type", choices=[e.value for e in AuditEventType], help="按事件类型过滤")
    audit_parser.add_argument("--limit", type=int, default=100, help="返回条数限制")
    audit_parser.add_argument("--export", help="导出日志到文件")
    audit_parser.add_argument("--stats", action="store_true", help="显示统计信息")

    # report 命令
    report_parser = subparsers.add_parser("report", help="生成合规报告")
    report_parser.add_argument("--output", required=True, help="输出文件路径")
    report_parser.add_argument(
        "--format",
        choices=[f.value for f in ReportFormat],
        default="json",
        help="报告格式"
    )
    report_parser.add_argument("--days", type=int, default=7, help="报告统计天数")
    report_parser.add_argument("--title", default="合规报告", help="报告标题")

    # config 命令
    config_parser = subparsers.add_parser("config", help="配置管理")
    config_parser.add_argument("--show", action="store_true", help="显示当前配置")
    config_parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="设置配置项")

    return parser


def handle_scan(args: argparse.Namespace) -> int:
    """处理扫描命令"""
    # 获取内容
    if args.file:
        try:
            content = Path(args.file).read_text(encoding="utf-8")
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            return 1
    elif args.content:
        content = args.content
    else:
        print("Error: 请提供内容或使用 -f 指定文件", file=sys.stderr)
        return 1

    # 创建检测器
    detector = ContentDetector()

    # 指定检测类型
    detection_types = None
    if args.type:
        detection_types = {DetectionType[t] for t in args.type}

    # 执行检测
    result = detector.detect(content, detection_types=detection_types)

    # 输出结果
    if args.format == "json":
        output = result.to_json()
    else:
        output = format_detection_result(result)

    if args.output:
        try:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"结果已保存到: {args.output}")
        except Exception as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            return 1
    else:
        print(output)

    return 0


def format_detection_result(result) -> str:
    """格式化检测结果为文本"""
    lines = [
        "=" * 50,
        "检测结果",
        "=" * 50,
        f"内容ID: {result.content_id}",
        f"时间戳: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
        f"处理时间: {result.processing_time_ms:.2f}ms",
        f"总体风险: {result.overall_risk.name}",
        "-" * 50,
    ]

    if result.matches:
        lines.append(f"发现 {len(result.matches)} 处匹配:")
        for i, match in enumerate(result.matches, 1):
            lines.append(f"\n[{i}] {match.type.name}")
            lines.append(f"    风险等级: {match.risk_level.name}")
            lines.append(f"    匹配文本: {match.matched_text}")
            lines.append(f"    位置: {match.position}")
            lines.append(f"    置信度: {match.confidence:.2f}")
            lines.append(f"    描述: {match.description}")
    else:
        lines.append("未发现敏感内容")

    lines.append("=" * 50)
    return "\n".join(lines)


def handle_rules(args: argparse.Namespace) -> int:
    """处理规则命令"""
    engine = RuleEngine()

    if args.list:
        rules = engine.list_rules()
        if not rules:
            print("暂无规则")
            return 0

        print(f"{'ID':<20} {'名称':<30} {'动作':<10} {'优先级':<8} {'状态':<8}")
        print("-" * 80)
        for rule in rules:
            status = "启用" if rule.enabled else "禁用"
            print(f"{rule.id:<20} {rule.name:<30} {rule.action.value:<10} {rule.priority:<8} {status:<8}")

    elif args.add:
        try:
            rule_data = json.loads(args.add)
            rule = Rule.from_dict(rule_data)
            engine.add_rule(rule)
            print(f"规则已添加: {rule.id}")
        except json.JSONDecodeError as e:
            print(f"JSON解析错误: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"添加规则失败: {e}", file=sys.stderr)
            return 1

    elif args.remove:
        if engine.remove_rule(args.remove):
            print(f"规则已移除: {args.remove}")
        else:
            print(f"规则不存在: {args.remove}", file=sys.stderr)
            return 1

    elif args.enable:
        rule = engine.get_rule(args.enable)
        if rule:
            rule.enabled = True
            print(f"规则已启用: {args.enable}")
        else:
            print(f"规则不存在: {args.enable}", file=sys.stderr)
            return 1

    elif args.disable:
        rule = engine.get_rule(args.disable)
        if rule:
            rule.enabled = False
            print(f"规则已禁用: {args.disable}")
        else:
            print(f"规则不存在: {args.disable}", file=sys.stderr)
            return 1

    elif args.export:
        try:
            engine.save_to_file(args.export)
            print(f"规则已导出到: {args.export}")
        except Exception as e:
            print(f"导出失败: {e}", file=sys.stderr)
            return 1

    elif args.import_file:
        try:
            engine.load_from_file(args.import_file)
            print(f"规则已从 {args.import_file} 导入")
        except Exception as e:
            print(f"导入失败: {e}", file=sys.stderr)
            return 1

    elif args.init_default:
        rules = engine.create_default_rules()
        print(f"已创建 {len(rules)} 条默认规则")

    else:
        print("请指定操作，使用 --help 查看帮助")
        return 1

    return 0


def handle_audit(args: argparse.Namespace) -> int:
    """处理审计命令"""
    # 创建审计日志记录器
    storage = FileAuditStorage("audit.log")
    logger = AuditLogger(storage)

    if args.query:
        start_time = datetime.now() - timedelta(hours=args.hours)
        level = AuditLevel(args.level) if args.level else None
        event_type = AuditEventType(args.event_type) if args.event_type else None

        entries = logger.query(
            start_time=start_time,
            level=level,
            event_type=event_type,
            limit=args.limit,
        )

        if not entries:
            print("未找到匹配的日志条目")
            return 0

        print(f"{'时间':<20} {'级别':<10} {'类型':<20} {'来源':<20} {'消息'}")
        print("-" * 100)
        for entry in entries:
            timestamp = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp:<20} {entry.level.value:<10} {entry.event_type.value:<20} {entry.source:<20} {entry.message[:30]}...")

    elif args.export:
        count = logger.export_to_file(args.export)
        print(f"已导出 {count} 条日志到: {args.export}")

    elif args.stats:
        stats = logger.get_stats(hours=args.hours)
        print(json.dumps(stats, indent=2, ensure_ascii=False))

    else:
        print("请指定操作，使用 --help 查看帮助")
        return 1

    return 0


def handle_report(args: argparse.Namespace) -> int:
    """处理报告命令"""
    reporter = ComplianceReporter()

    period_end = datetime.now()
    period_start = period_end - timedelta(days=args.days)

    # 生成报告
    report = reporter.generate_report(
        title=args.title,
        period_start=period_start,
        period_end=period_end,
    )

    # 导出报告
    format_map = {
        "json": ReportFormat.JSON,
        "html": ReportFormat.HTML,
        "markdown": ReportFormat.MARKDOWN,
        "csv": ReportFormat.CSV,
    }
    report_format = format_map.get(args.format, ReportFormat.JSON)

    try:
        output_path = reporter.export(report, args.output, report_format)
        print(f"报告已生成: {output_path}")
        print(f"总体状态: {report.overall_status}")
    except Exception as e:
        print(f"生成报告失败: {e}", file=sys.stderr)
        return 1

    return 0


def handle_config(args: argparse.Namespace) -> int:
    """处理配置命令"""
    config_file = Path.home() / ".chatguard" / "config.json"

    if args.show:
        if config_file.exists():
            config = json.loads(config_file.read_text(encoding="utf-8"))
            print(json.dumps(config, indent=2, ensure_ascii=False))
        else:
            print("配置文件不存在")

    elif args.set:
        key, value = args.set
        config = {}
        if config_file.exists():
            config = json.loads(config_file.read_text(encoding="utf-8"))

        # 尝试解析为JSON类型
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass  # 保持为字符串

        config[key] = value
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text(json.dumps(config, indent=2, ensure_ascii=False))
        print(f"配置已更新: {key} = {value}")

    else:
        print("请指定操作，使用 --help 查看帮助")
        return 1

    return 0


def main(args: Optional[List[str]] = None) -> int:
    """主入口函数"""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 1

    command_handlers = {
        "scan": handle_scan,
        "rules": handle_rules,
        "audit": handle_audit,
        "report": handle_report,
        "config": handle_config,
    }

    handler = command_handlers.get(parsed_args.command)
    if handler:
        return handler(parsed_args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
