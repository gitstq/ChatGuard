"""
合规报告生成器模块

提供合规报告生成、导出和分析功能，支持多种报告格式。
"""

import json
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union
from datetime import datetime, timedelta
from pathlib import Path

from .detector import DetectionResult, RiskLevel, DetectionType
from .audit import AuditLogger, AuditEntry, AuditLevel, AuditEventType


class ReportFormat(Enum):
    """报告格式枚举"""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    CSV = "csv"
    PDF = "pdf"


@dataclass
class ComplianceMetric:
    """合规指标"""
    name: str
    value: Any
    threshold: Optional[Any] = None
    status: str = "unknown"  # "pass", "fail", "warning", "unknown"
    description: str = ""


@dataclass
class ComplianceSection:
    """报告章节"""
    title: str
    content: str
    metrics: List[ComplianceMetric] = field(default_factory=list)
    subsections: List["ComplianceSection"] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """合规报告"""
    report_id: str
    title: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    summary: str
    sections: List[ComplianceSection]
    overall_status: str  # "compliant", "non_compliant", "partial"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "report_id": self.report_id,
            "title": self.title,
            "generated_at": self.generated_at.isoformat(),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "summary": self.summary,
            "overall_status": self.overall_status,
            "sections": [
                {
                    "title": s.title,
                    "content": s.content,
                    "metrics": [
                        {
                            "name": m.name,
                            "value": m.value,
                            "threshold": m.threshold,
                            "status": m.status,
                            "description": m.description,
                        }
                        for m in s.metrics
                    ],
                }
                for s in self.sections
            ],
            "metadata": self.metadata,
        }


class ComplianceReporter:
    """合规报告生成器"""

    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        self.audit_logger = audit_logger
        self._report_counter = 0

    def _generate_report_id(self) -> str:
        """生成报告ID"""
        self._report_counter += 1
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"RPT-{timestamp}-{self._report_counter:04d}"

    def generate_report(
        self,
        title: str,
        period_start: datetime,
        period_end: datetime,
        detection_results: Optional[List[DetectionResult]] = None,
        audit_entries: Optional[List[AuditEntry]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ComplianceReport:
        """
        生成合规报告

        Args:
            title: 报告标题
            period_start: 统计开始时间
            period_end: 统计结束时间
            detection_results: 检测结果列表
            audit_entries: 审计日志列表
            metadata: 元数据

        Returns:
            ComplianceReport: 合规报告
        """
        sections = []

        # 概览章节
        sections.append(self._generate_overview_section(
            period_start, period_end, detection_results, audit_entries
        ))

        # 检测结果章节
        if detection_results:
            sections.append(self._generate_detection_section(detection_results))

        # 审计日志章节
        if audit_entries:
            sections.append(self._generate_audit_section(audit_entries))

        # 合规性评估章节
        sections.append(self._generate_compliance_assessment_section(
            detection_results, audit_entries
        ))

        # 计算总体状态
        overall_status = self._calculate_overall_status(sections)

        # 生成摘要
        summary = self._generate_summary(sections, overall_status)

        report = ComplianceReport(
            report_id=self._generate_report_id(),
            title=title,
            generated_at=datetime.now(),
            period_start=period_start,
            period_end=period_end,
            summary=summary,
            sections=sections,
            overall_status=overall_status,
            metadata=metadata or {},
        )

        # 记录报告生成
        if self.audit_logger:
            self.audit_logger.info(
                event_type=AuditEventType.COMPLIANCE_CHECK,
                source="ComplianceReporter",
                message=f"Generated compliance report: {title}",
                metadata={
                    "report_id": report.report_id,
                    "period_start": period_start.isoformat(),
                    "period_end": period_end.isoformat(),
                    "overall_status": overall_status,
                },
            )

        return report

    def _generate_overview_section(
        self,
        period_start: datetime,
        period_end: datetime,
        detection_results: Optional[List[DetectionResult]],
        audit_entries: Optional[List[AuditEntry]],
    ) -> ComplianceSection:
        """生成概览章节"""
        duration = period_end - period_start

        content = f"""
## 报告周期
- 开始时间: {period_start.strftime("%Y-%m-%d %H:%M:%S")}
- 结束时间: {period_end.strftime("%Y-%m-%d %H:%M:%S")}
- 统计时长: {duration.days}天 {duration.seconds // 3600}小时

## 数据概览
"""

        metrics = []

        if detection_results:
            total_scanned = len(detection_results)
            total_matches = sum(len(r.matches) for r in detection_results)
            high_risk = sum(1 for r in detection_results if r.overall_risk == RiskLevel.HIGH or r.overall_risk == RiskLevel.CRITICAL)

            content += f"""
- 扫描内容总数: {total_scanned}
- 检测匹配总数: {total_matches}
- 高风险内容数: {high_risk}
"""

            metrics.extend([
                ComplianceMetric(
                    name="total_scanned",
                    value=total_scanned,
                    description="扫描内容总数",
                ),
                ComplianceMetric(
                    name="total_matches",
                    value=total_matches,
                    description="检测匹配总数",
                ),
                ComplianceMetric(
                    name="high_risk_ratio",
                    value=round(high_risk / total_scanned * 100, 2) if total_scanned > 0 else 0,
                    threshold=10.0,
                    status="pass" if (high_risk / total_scanned * 100 if total_scanned > 0 else 0) < 10 else "warning",
                    description="高风险内容比例(%)",
                ),
            ])

        if audit_entries:
            total_events = len(audit_entries)
            critical_events = sum(1 for e in audit_entries if e.level == AuditLevel.CRITICAL)

            content += f"""
- 审计事件总数: {total_events}
- 严重事件数: {critical_events}
"""

            metrics.append(ComplianceMetric(
                name="critical_events",
                value=critical_events,
                threshold=0,
                status="pass" if critical_events == 0 else "fail",
                description="严重事件数",
            ))

        return ComplianceSection(
            title="报告概览",
            content=content,
            metrics=metrics,
        )

    def _generate_detection_section(
        self,
        detection_results: List[DetectionResult],
    ) -> ComplianceSection:
        """生成检测结果章节"""
        # 按类型统计
        type_stats: Dict[str, int] = {}
        risk_stats: Dict[str, int] = {}

        for result in detection_results:
            for match in result.matches:
                type_name = match.type.name
                risk_name = match.risk_level.name
                type_stats[type_name] = type_stats.get(type_name, 0) + 1
                risk_stats[risk_name] = risk_stats.get(risk_name, 0) + 1

        content = "## 检测结果统计\n\n"
        content += "### 按检测类型统计\n"
        for type_name, count in sorted(type_stats.items(), key=lambda x: x[1], reverse=True):
            content += f"- {type_name}: {count}\n"

        content += "\n### 按风险等级统计\n"
        for risk_name, count in sorted(risk_stats.items(), key=lambda x: x[1], reverse=True):
            content += f"- {risk_name}: {count}\n"

        metrics = [
            ComplianceMetric(
                name="pii_detections",
                value=type_stats.get("PII", 0),
                threshold=100,
                status="pass" if type_stats.get("PII", 0) < 100 else "warning",
                description="个人身份信息检测数",
            ),
            ComplianceMetric(
                name="critical_risk_count",
                value=risk_stats.get("CRITICAL", 0),
                threshold=0,
                status="pass" if risk_stats.get("CRITICAL", 0) == 0 else "fail",
                description="严重风险数量",
            ),
        ]

        return ComplianceSection(
            title="内容安全检测",
            content=content,
            metrics=metrics,
        )

    def _generate_audit_section(
        self,
        audit_entries: List[AuditEntry],
    ) -> ComplianceSection:
        """生成审计日志章节"""
        # 按级别统计
        level_stats: Dict[str, int] = {}
        event_stats: Dict[str, int] = {}

        for entry in audit_entries:
            level_stats[entry.level.value] = level_stats.get(entry.level.value, 0) + 1
            event_stats[entry.event_type.value] = event_stats.get(entry.event_type.value, 0) + 1

        content = "## 审计事件统计\n\n"
        content += "### 按日志级别统计\n"
        for level, count in sorted(level_stats.items(), key=lambda x: x[1], reverse=True):
            content += f"- {level}: {count}\n"

        content += "\n### 按事件类型统计\n"
        for event_type, count in sorted(event_stats.items(), key=lambda x: x[1], reverse=True):
            content += f"- {event_type}: {count}\n"

        return ComplianceSection(
            title="审计日志分析",
            content=content,
        )

    def _generate_compliance_assessment_section(
        self,
        detection_results: Optional[List[DetectionResult]],
        audit_entries: Optional[List[AuditEntry]],
    ) -> ComplianceSection:
        """生成合规性评估章节"""
        content = "## 合规性评估\n\n"

        assessments = []

        # 数据保护评估
        if detection_results:
            pii_count = sum(
                1 for r in detection_results
                for m in r.matches if m.type == DetectionType.PII
            )
            if pii_count == 0:
                assessments.append("数据保护: 未检测到个人身份信息泄露风险")
            elif pii_count < 10:
                assessments.append(f"数据保护: 检测到{pii_count}处个人身份信息，建议加强数据保护措施")
            else:
                assessments.append(f"数据保护: 检测到{pii_count}处个人身份信息，存在数据泄露风险")

        # 安全事件评估
        if audit_entries:
            critical_count = sum(1 for e in audit_entries if e.level == AuditLevel.CRITICAL)
            if critical_count == 0:
                assessments.append("安全事件: 报告期内无严重安全事件")
            else:
                assessments.append(f"安全事件: 报告期内发生{critical_count}起严重安全事件，需立即处理")

        content += "\n".join(f"- {a}" for a in assessments)

        return ComplianceSection(
            title="合规性评估",
            content=content,
        )

    def _calculate_overall_status(self, sections: List[ComplianceSection]) -> str:
        """计算总体合规状态"""
        failed_metrics = 0
        total_metrics = 0

        for section in sections:
            for metric in section.metrics:
                total_metrics += 1
                if metric.status == "fail":
                    failed_metrics += 1

        if failed_metrics == 0:
            return "compliant"
        elif failed_metrics / total_metrics < 0.2:
            return "partial"
        else:
            return "non_compliant"

    def _generate_summary(self, sections: List[ComplianceSection], overall_status: str) -> str:
        """生成报告摘要"""
        status_desc = {
            "compliant": "符合合规要求",
            "partial": "部分符合合规要求",
            "non_compliant": "不符合合规要求",
        }

        return f"本报告期间整体合规状态: {status_desc.get(overall_status, '未知')}。详细分析请参见各章节。"

    def export(
        self,
        report: ComplianceReport,
        filepath: Union[str, Path],
        format: ReportFormat = ReportFormat.JSON,
    ) -> Path:
        """
        导出报告

        Args:
            report: 合规报告
            filepath: 输出文件路径
            format: 导出格式

        Returns:
            Path: 输出文件路径
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        if format == ReportFormat.JSON:
            self._export_json(report, filepath)
        elif format == ReportFormat.HTML:
            self._export_html(report, filepath)
        elif format == ReportFormat.MARKDOWN:
            self._export_markdown(report, filepath)
        elif format == ReportFormat.CSV:
            self._export_csv(report, filepath)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return filepath

    def _export_json(self, report: ComplianceReport, filepath: Path) -> None:
        """导出为JSON"""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)

    def _export_html(self, report: ComplianceReport, filepath: Path) -> None:
        """导出为HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{report.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; border-bottom: 1px solid #ddd; padding-bottom: 10px; }}
        .header {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .status-compliant {{ color: green; }}
        .status-partial {{ color: orange; }}
        .status-non-compliant {{ color: red; }}
        .metric {{ margin: 10px 0; padding: 10px; background: #fafafa; border-left: 3px solid #ddd; }}
        .metric-pass {{ border-left-color: green; }}
        .metric-fail {{ border-left-color: red; }}
        .metric-warning {{ border-left-color: orange; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{report.title}</h1>
        <p><strong>报告ID:</strong> {report.report_id}</p>
        <p><strong>生成时间:</strong> {report.generated_at.strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>统计周期:</strong> {report.period_start.strftime("%Y-%m-%d")} 至 {report.period_end.strftime("%Y-%m-%d")}</p>
        <p><strong>总体状态:</strong> <span class="status-{report.overall_status}">{report.overall_status.upper()}</span></p>
        <p><strong>摘要:</strong> {report.summary}</p>
    </div>
"""

        for section in report.sections:
            html += f"<h2>{section.title}</h2>\n"
            html += f'<div class="content">{section.content.replace(chr(10), "<br>")}</div>\n'

            if section.metrics:
                html += "<h3>指标</h3><table>\n"
                html += "<tr><th>指标名称</th><th>值</th><th>阈值</th><th>状态</th><th>描述</th></tr>\n"
                for metric in section.metrics:
                    status_class = f"metric-{metric.status}"
                    html += f"<tr class='{status_class}'>\n"
                    html += f"<td>{metric.name}</td>\n"
                    html += f"<td>{metric.value}</td>\n"
                    html += f"<td>{metric.threshold or '-'}</td>\n"
                    html += f"<td>{metric.status.upper()}</td>\n"
                    html += f"<td>{metric.description}</td>\n"
                    html += "</tr>\n"
                html += "</table>\n"

        html += "</body></html>"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

    def _export_markdown(self, report: ComplianceReport, filepath: Path) -> None:
        """导出为Markdown"""
        md = f"# {report.title}\n\n"
        md += f"**报告ID:** {report.report_id}\n\n"
        generated_at = report.generated_at.strftime("%Y-%m-%d %H:%M:%S")
        md += f"**生成时间:** {generated_at}\n\n"
        period_start = report.period_start.strftime("%Y-%m-%d")
        period_end = report.period_end.strftime("%Y-%m-%d")
        md += f"**统计周期:** {period_start} 至 {period_end}\n\n"
        md += f"**总体状态:** {report.overall_status.upper()}\n\n"
        md += f"**摘要:** {report.summary}\n\n"
        md += "---\n\n"

        for section in report.sections:
            md += f"## {section.title}\n\n"
            md += f"{section.content}\n\n"

            if section.metrics:
                md += "### 指标\n\n"
                md += "| 指标名称 | 值 | 阈值 | 状态 | 描述 |\n"
                md += "|---------|-----|------|------|------|\n"
                for metric in section.metrics:
                    threshold = metric.threshold or "-"
                    md += f"| {metric.name} | {metric.value} | {threshold} | {metric.status.upper()} | {metric.description} |\n"
                md += "\n"

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md)

    def _export_csv(self, report: ComplianceReport, filepath: Path) -> None:
        """导出为CSV"""
        import csv

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Report ID", report.report_id])
            writer.writerow(["Title", report.title])
            writer.writerow(["Generated At", report.generated_at.isoformat()])
            writer.writerow(["Period", f"{report.period_start.isoformat()} to {report.period_end.isoformat()}"])
            writer.writerow(["Overall Status", report.overall_status])
            writer.writerow([])

            for section in report.sections:
                writer.writerow([section.title])
                writer.writerow([section.content])
                writer.writerow([])

                if section.metrics:
                    writer.writerow(["Metric", "Value", "Threshold", "Status", "Description"])
                    for metric in section.metrics:
                        writer.writerow([
                            metric.name,
                            metric.value,
                            metric.threshold,
                            metric.status,
                            metric.description,
                        ])
                    writer.writerow([])
