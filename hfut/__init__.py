"""合肥工业大学 CAS / 门户 / 教务系统逆向登录客户端包。

说明：
- 核心逻辑在 hfut.client.Reverse，请以 ``from hfut.client import Reverse`` 方式导入。
- 这里不主动导入 client，避免仅使用 config/headers 的轻量脚本（如 vercode.py）
  也必须携带 pycryptodome 等重依赖。
"""

__all__ = []
