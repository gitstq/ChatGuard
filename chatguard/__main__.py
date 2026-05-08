"""
ChatGuard 模块入口

允许通过 `python -m chatguard` 运行命令行工具。
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
