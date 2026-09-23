"""统一的日志输出与 JSON 美化工具。

约定：
- 库代码只通过 ``get_logger(__name__)`` 取 logger 并记录日志，
  不在库内添加 handler，也不使用 ``print``；
- 输出格式与目标流由入口脚本（``main.py`` / ``vercode.py``）调用
  ``setup_logging()`` 统一配置，默认输出到 stdout，级别 INFO。
"""

import json
import logging
import os
import sys
from typing import Any, Optional

# 输出格式：时间 [级别] 来源: 消息
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DATE_FORMAT = "%H:%M:%S"

# 可用环境变量覆盖默认级别，例如 LOG_LEVEL=DEBUG（也可写在 .env 中）
LEVEL_ENV_VAR = "LOG_LEVEL"


class StdoutHandler(logging.Handler):
    """把日志写入“当前”的 ``sys.stdout``。

    ``logging.StreamHandler`` 会在构造时绑定那一刻的流对象，之后对 stdout
    的重定向（如 ``redirect_stdout``、pytest 的输出捕获）不会再生效。
    这里每次输出都重新获取 ``sys.stdout``，行为与直接 ``print`` 保持一致。
    """

    # 与 logging.StreamHandler 保持一致（Handler 基类上没有这个属性）
    terminator = "\n"

    def emit(self, record: logging.LogRecord) -> None:
        try:
            stream = sys.stdout
            stream.write(self.format(record) + self.terminator)
            stream.flush()
        except Exception:
            # 与标准库一致：输出失败交给 handleError，不影响主流程
            self.handleError(record)


def _level_from_env() -> int:
    """读取 ``LOG_LEVEL`` 环境变量，未设置或非法时回退到 INFO。"""
    name = os.getenv(LEVEL_ENV_VAR, "").strip().upper()
    if not name:
        return logging.INFO

    level = logging.getLevelName(name)
    if isinstance(level, int):
        return level

    # 该函数在 handler 安装之后调用，因此这里的告警用户可以看到
    get_logger(__name__).warning(
        "环境变量 %s=%s 不是合法的日志级别，已回退到 INFO", LEVEL_ENV_VAR, name
    )
    return logging.INFO


def setup_logging(level: Optional[int] = None) -> None:
    """配置根 logger 的输出格式与级别。

    重复调用是幂等的，不会重复添加 handler。``level`` 缺省时读取
    环境变量 ``LOG_LEVEL``。
    """
    root = logging.getLogger()
    if not any(isinstance(handler, StdoutHandler) for handler in root.handlers):
        handler = StdoutHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        root.addHandler(handler)

    root.setLevel(_level_from_env() if level is None else level)


def get_logger(name: str) -> logging.Logger:
    """获取模块级 logger，用法与 ``logging.getLogger`` 一致。"""
    return logging.getLogger(name)


def format_json(data: Any) -> str:
    """把接口返回的数据格式化为带缩进的 JSON，便于阅读中文与嵌套结构。"""
    return json.dumps(data, ensure_ascii=False, indent=2)
