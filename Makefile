# ChatGuard Makefile
# 提供常用的构建、测试和开发命令

.PHONY: help install install-dev test test-cov lint format clean build publish docs

# 默认目标
help:
	@echo "ChatGuard 构建工具"
	@echo ""
	@echo "可用命令:"
	@echo "  make install      - 安装包"
	@echo "  make install-dev  - 安装开发依赖"
	@echo "  make test         - 运行测试"
	@echo "  make test-cov     - 运行测试并生成覆盖率报告"
	@echo "  make lint         - 运行代码检查"
	@echo "  make format       - 格式化代码"
	@echo "  make clean        - 清理构建文件"
	@echo "  make build        - 构建分发包"
	@echo "  make publish      - 发布到PyPI"
	@echo "  make docs         - 生成文档"

# 安装
install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

# 测试
test:
	python -m pytest tests/ -v

test-cov:
	python -m pytest tests/ -v --cov=chatguard --cov-report=html --cov-report=term

# 代码质量
lint:
	python -m flake8 chatguard tests
	python -m mypy chatguard

format:
	python -m black chatguard tests
	python -m isort chatguard tests

format-check:
	python -m black --check chatguard tests
	python -m isort --check-only chatguard tests

# 清理
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf __pycache__/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete

# 构建
build: clean
	python -m build

# 发布
publish-test:
	python -m twine upload --repository testpypi dist/*

publish:
	python -m twine upload dist/*

# 文档
docs:
	cd docs && make html

# 运行示例
example:
	python -m chatguard scan "测试内容: 13800138000"

# 运行CLI
cli:
	python -m chatguard --help

# 检查包
 check:
	python -m twine check dist/*

# 安全扫描
security:
	python -m bandit -r chatguard/

# 类型检查
type-check:
	python -m mypy chatguard

# 全部检查（CI使用）
ci: lint type-check test

# 开发模式（安装所有依赖并运行测试）
dev: install-dev test
	@echo "开发环境准备完成"
