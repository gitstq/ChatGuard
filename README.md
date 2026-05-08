<div align="center">

# 🛡️ ChatGuard

**AI对话实时合规检测引擎**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-orange)](.)
[![Tests](https://img.shields.io/badge/Tests-92%20passed-brightgreen)](.)

[English](#english) | [简体中文](#简体中文) | [繁體中文](#繁體中文)

</div>

---

<a name="简体中文"></a>
## 🎉 项目介绍

ChatGuard 是一款**轻量级AI对话实时合规检测引擎**，专为AI聊天应用、客服系统、内容平台设计。它能够在毫秒级时间内检测对话中的敏感信息、违规内容，并实时阻断风险对话，保护用户隐私和平台安全。

### 💡 灵感来源

随着AI对话系统的普及，内容安全和隐私保护成为关键挑战：
- 用户可能在对话中无意泄露身份证号、手机号等PII信息
- AI可能生成不当、有害或违规内容
- 企业需要满足GDPR、CCPA等合规要求
- 实时检测需求对性能要求极高

ChatGuard 应运而生，提供**零依赖、高性能、易集成**的解决方案。

### ✨ 核心特性

| 特性 | 描述 |
|------|------|
| 🚀 **零依赖** | 纯Python标准库实现，无需安装任何第三方包 |
| ⚡ **实时检测** | 毫秒级响应，支持流式内容检测 |
| 🛡️ **多维检测** | PII识别、敏感词过滤、违规内容检测 |
| 📊 **智能评分** | 多维度风险评分，精准分级管控 |
| 📝 **完整审计** | 全量对话日志，支持合规追溯 |
| 📈 **丰富报告** | JSON/Markdown/HTML多格式报告导出 |
| ⚙️ **灵活配置** | YAML规则引擎，支持热更新 |
| 🔌 **易于集成** | 一行代码接入现有系统 |

---

## 🚀 快速开始

### 环境要求

- Python 3.8 或更高版本
- 无其他依赖（零依赖设计）

### 安装

```bash
# 从PyPI安装（推荐）
pip install chatguard

# 或从源码安装
git clone https://github.com/gitstq/ChatGuard.git
cd ChatGuard
pip install -e .
```

### 基本使用

#### 1. 命令行扫描

```bash
# 扫描单条文本
chatguard scan "需要检测的文本内容"

# 扫描文件
chatguard scan-file input.txt

# 交互式模式
chatguard interactive
```

#### 2. Python API

```python
from chatguard import ContentScanner

# 创建扫描器
scanner = ContentScanner()

# 扫描文本
result = scanner.scan("我的手机号是13800138000")

print(f"风险评分: {result.risk_score}")
print(f"是否阻断: {result.blocked}")
print(f"检测结果: {len(result.detections)} 个问题")
```

#### 3. 高级用法

```python
from chatguard import ContentScanner, ScanConfig
from chatguard.detector import ContentDetector, DetectionType

# 自定义配置
config = ScanConfig(
    block_threshold=80.0,  # 阻断阈值
    warn_threshold=50.0,   # 警告阈值
)

scanner = ContentScanner(config=config)

# 添加自定义检测规则
detector = ContentDetector()
detector.add_pattern(
    DetectionType.SENSITIVE_WORD,
    r"自定义敏感词"
)

# 批量检测
texts = ["文本1", "文本2", "文本3"]
results = detector.batch_detect(texts)
```

---

## 📖 详细使用指南

### 检测类型

ChatGuard 支持以下检测类型：

| 类型 | 说明 | 示例 |
|------|------|------|
| 🔴 **PII** | 个人身份信息 | 身份证号、手机号、邮箱、银行卡号 |
| 🟠 **敏感词** | 敏感关键词 | 密码、密钥、令牌 |
| 🟡 **不当言论** | 辱骂、攻击性语言 | 脏话、人身攻击 |
| 🔴 **暴力内容** | 暴力、恐怖相关 | 杀人、爆炸、袭击 |
| 🔴 **违法违规** | 违法行为 | 毒品、枪支、黑客 |
| 🟠 **隐私泄露** | 隐私相关信息 | 隐私、机密、个人信息 |

### 规则引擎

```python
from chatguard.rules import RuleEngine

# 创建规则引擎
engine = RuleEngine()

# 查看所有规则
rules = engine.get_all_rules()

# 启用/禁用规则
engine.enable_rule("pii_phone")
engine.disable_rule("toxic_mild")

# 自定义规则
from chatguard.rules import Rule

new_rule = Rule(
    id="custom_rule",
    name="自定义规则",
    description="检测特定内容",
    pattern=r"特定模式",
    risk_level="high",
    category="custom",
    action="block"
)
engine.add_rule(new_rule)
```

### 审计日志

```python
from chatguard.audit import AuditLogger

# 创建审计日志器
logger = AuditLogger(log_dir="./logs")

# 记录日志
logger.log(
    session_id="session_001",
    input_text="用户输入",
    risk_score=75.0,
    detections=[{"type": "pii"}],
    action_taken="block",
    blocked=True
)

# 查询日志
entries = logger.query(
    session_id="session_001",
    blocked_only=True
)

# 获取统计
stats = logger.get_stats()
```

### 合规报告

```python
from chatguard.audit import AuditLogger
from chatguard.reporter import ComplianceReporter

audit_logger = AuditLogger()
reporter = ComplianceReporter(audit_logger)

# 生成摘要报告
report = reporter.generate_summary_report()

# 导出为不同格式
reporter.export_to_json(report, "report.json")
reporter.export_to_markdown(report, "report.md")
reporter.generate_html_report(report, "report.html")
```

---

## 💡 设计思路与迭代规划

### 技术选型

- **纯标准库实现**：零外部依赖，降低部署复杂度
- **正则表达式引擎**：高性能模式匹配
- **数据类**：类型安全，代码清晰
- **生成器**：流式处理，内存友好

### 架构设计

```
┌─────────────────────────────────────────┐
│           ChatGuard 架构                │
├─────────────────────────────────────────┤
│  CLI Layer  │  API Layer  │  Web Layer  │
├─────────────┴─────────────┴─────────────┤
│           ContentScanner                │
│  ┌─────────┬─────────┬───────────────┐  │
│  │ Detector│  Rules  │  Audit Logger │  │
│  └─────────┴─────────┴───────────────┘  │
├─────────────────────────────────────────┤
│         Compliance Reporter             │
└─────────────────────────────────────────┘
```

### 迭代规划

- [x] v1.0.0 - 核心功能实现
- [ ] v1.1.0 - 支持更多检测类型（图片、链接）
- [ ] v1.2.0 - Web UI 管理界面
- [ ] v1.3.0 - 机器学习模型集成
- [ ] v2.0.0 - 分布式部署支持

---

## 📦 打包与部署

### 构建分发包

```bash
# 安装构建工具
pip install build twine

# 构建
python -m build

# 发布到PyPI
python -m twine upload dist/*
```

### Docker 部署

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install -e .

CMD ["chatguard", "interactive"]
```

---

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

### 提交规范

- `feat:` 新功能
- `fix:` 修复问题
- `docs:` 文档更新
- `refactor:` 代码重构
- `test:` 测试相关

### 开发流程

```bash
# 克隆仓库
git clone https://github.com/gitstq/ChatGuard.git

# 创建分支
git checkout -b feature/your-feature

# 提交更改
git commit -m "feat: 添加新功能"

# 推送分支
git push origin feature/your-feature
```

---

## 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

---

<a name="english"></a>
## 🎉 Introduction

ChatGuard is a **lightweight AI chat real-time compliance detection engine** designed for AI chat applications, customer service systems, and content platforms. It can detect sensitive information and non-compliant content in conversations within milliseconds, and block risky conversations in real-time to protect user privacy and platform security.

### ✨ Key Features

- 🚀 **Zero Dependencies** - Pure Python standard library implementation
- ⚡ **Real-time Detection** - Millisecond-level response with streaming support
- 🛡️ **Multi-dimensional Detection** - PII recognition, sensitive word filtering
- 📊 **Intelligent Scoring** - Multi-dimensional risk assessment
- 📝 **Complete Audit** - Full conversation logging for compliance
- 📈 **Rich Reports** - JSON/Markdown/HTML export formats
- ⚙️ **Flexible Configuration** - YAML rule engine with hot reload
- 🔌 **Easy Integration** - One-line integration with existing systems

### 🚀 Quick Start

```bash
# Install
pip install chatguard

# Scan text
chatguard scan "Text to be scanned"

# Interactive mode
chatguard interactive
```

```python
from chatguard import ContentScanner

scanner = ContentScanner()
result = scanner.scan("My phone number is 13800138000")

print(f"Risk Score: {result.risk_score}")
print(f"Blocked: {result.blocked}")
```

---

<a name="繁體中文"></a>
## 🎉 專案介紹

ChatGuard 是一款**輕量級AI對話即時合規檢測引擎**，專為AI聊天應用、客服系統、內容平台設計。它能夠在毫秒級時間內檢測對話中的敏感資訊、違規內容，並即時阻斷風險對話，保護使用者隱私和平台安全。

### ✨ 核心特性

- 🚀 **零依賴** - 純Python標準庫實現
- ⚡ **即時檢測** - 毫秒級響應，支援串流內容檢測
- 🛡️ **多維檢測** - PII識別、敏感詞過濾、違規內容檢測
- 📊 **智慧評分** - 多維度風險評分，精準分級管控
- 📝 **完整審計** - 全量對話日誌，支援合規追溯
- 📈 **豐富報告** - JSON/Markdown/HTML多格式報告匯出
- ⚙️ **靈活配置** - YAML規則引擎，支援熱更新
- 🔌 **易於整合** - 一行程式碼接入現有系統

### 🚀 快速開始

```bash
# 安裝
pip install chatguard

# 掃描文字
chatguard scan "需要檢測的文字內容"

# 互動式模式
chatguard interactive
```

```python
from chatguard import ContentScanner

scanner = ContentScanner()
result = scanner.scan("我的手機號是13800138000")

print(f"風險評分: {result.risk_score}")
print(f"是否阻斷: {result.blocked}")
```

---

<div align="center">

**Made with ❤️ by ChatGuard Team**

[GitHub](https://github.com/gitstq/ChatGuard) | [Issues](https://github.com/gitstq/ChatGuard/issues) | [License](LICENSE)

</div>
