"""公共请求头构建器。

将 CAS / 门户 / 教务系统三类请求的请求头按场景归纳成函数，
供 hfut.client 各方法调用，消除原先 reverse.py 中重复的内联 headers dict。

每个构建函数返回一份可复用的 dict，传入的 extra 会覆盖同名默认头。
"""

from __future__ import annotations

from typing import Dict, Optional

from hfut import config

# 浏览器 UA（Chrome 142），CAS / 门户 / 教务通用
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
)

# 各场景 Accept 值
_ACCEPT_HTML = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)
_ACCEPT_JSON = "application/json, text/plain, */*"
_ACCEPT_JSON_XHR = "application/json, text/javascript, */*; q=0.01"
_ACCEPT_IMAGE = (
    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
)

_ACCEPT_LANGUAGE = "en-GB,en;q=0.9,zh-CN;q=0.8,zh;q=0.7"

# CAS / 门户请求统一携带的浏览器指纹头
_CHROME_HINTS = {
    "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}


def _merge(headers: Dict[str, str], extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """把 extra 中的头合并到 headers 上并返回（覆盖同名键）。"""
    if extra:
        headers.update(extra)
    return headers


def page(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """HTML 页面导航请求（CAS login / authorize / 门户首页）。

    默认 Sec-Fetch-Site 为 same-origin；跨站请求请通过 extra 覆盖。
    """
    return _merge(
        {
            "Accept": _ACCEPT_HTML,
            "Accept-Language": _ACCEPT_LANGUAGE,
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": USER_AGENT,
            **_CHROME_HINTS,
        },
        extra,
    )


def xhr_json(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """基于 fetch 的 JSON XHR 请求（门户 one.hfut.edu.cn 查询接口）。

    Accept 为 ``application/json, text/plain, */*``。
    """
    return _merge(
        {
            "Accept": _ACCEPT_JSON,
            "Accept-Language": _ACCEPT_LANGUAGE,
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": USER_AGENT,
            **_CHROME_HINTS,
        },
        extra,
    )


def cas_xhr_json(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """CAS 平台自身的 JSON XHR 请求（init / identity 校验接口）。

    与门户接口不同：Accept 带 ``q=0.01``，且携带 X-Requested-With。
    默认以 CAS 登录页为 Referer。
    """
    return _merge(
        {
            "Accept": _ACCEPT_JSON_XHR,
            "Accept-Language": _ACCEPT_LANGUAGE,
            "Connection": "keep-alive",
            "Referer": config.CAS_LOGIN_REFERER,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": USER_AGENT,
            "X-Requested-With": "XMLHttpRequest",
            **_CHROME_HINTS,
        },
        extra,
    )


def image(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """图形验证码图片请求（默认以 CAS 登录页为 Referer）。"""
    return _merge(
        {
            "Accept": _ACCEPT_IMAGE,
            "Accept-Language": _ACCEPT_LANGUAGE,
            "Connection": "keep-alive",
            "Referer": config.CAS_LOGIN_REFERER,
            "Sec-Fetch-Dest": "image",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": USER_AGENT,
            **_CHROME_HINTS,
        },
        extra,
    )


def eams_page(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """教务系统（eams，http 明文）HTML 页面请求。

    旧系统不携带 sec-ch 指纹头，而是使用 Proxy-Connection。
    """
    return _merge(
        {
            "Accept": _ACCEPT_HTML,
            "Accept-Language": _ACCEPT_LANGUAGE,
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Proxy-Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": USER_AGENT,
        },
        extra,
    )


def eams_json(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """教务系统 JSON 接口请求（http 明文，无 sec-ch 指纹头）。"""
    return _merge(
        {
            "Accept": _ACCEPT_JSON,
            "Accept-Language": _ACCEPT_LANGUAGE,
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Proxy-Connection": "keep-alive",
            "User-Agent": USER_AGENT,
        },
        extra,
    )
