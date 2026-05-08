"""
ChatGuard 安装配置
"""

from setuptools import setup, find_packages
from pathlib import Path

# 读取README文件
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

setup(
    name="chatguard",
    version="1.0.0",
    author="ChatGuard Team",
    author_email="team@chatguard.dev",
    description="AI对话内容安全检测与合规管理系统",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/chatguard/chatguard",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Text Processing :: Linguistic",
    ],
    python_requires=">=3.8",
    install_requires=[
        # 纯Python实现，无外部依赖
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "isort>=5.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "chatguard=chatguard.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="ai, security, content-moderation, compliance, audit, chat, llm",
    project_urls={
        "Bug Reports": "https://github.com/chatguard/chatguard/issues",
        "Source": "https://github.com/chatguard/chatguard",
        "Documentation": "https://chatguard.readthedocs.io/",
    },
)
