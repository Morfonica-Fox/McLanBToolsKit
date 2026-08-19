# Copyright (c) [2026] [Morfonica_Fox]
# [McLanBToolsKit] is licensed under Mulan PubL v2.
# You can use this software according to the terms and conditions of the Mulan PubL v2.
# You may obtain a copy of Mulan PubL v2 at:
#         http://license.coscl.org.cn/MulanPubL-2.0
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PubL v2 for more details.

from __future__ import annotations

import io
import re
from contextlib import suppress
from typing import Literal, NamedTuple, Sequence, TypeAlias

# import pydivert
from charset_normalizer import from_bytes

# fmt: off
COLOR_MAPPINGS_ANSI = {  # 废弃这个 -- Cbscfe
    "0": "30",  "1": "34",  "2": "32",  "3": "36",
    "4": "31",  "5": "35",  "6": "33",  "7": "37",
    "8": "90",  "9": "94",  "a": "92",  "b": "96",
    "c": "91",  "d": "95",  "e": "93",  "f": "97",
}

COLOR_MAPPINGS = {
    "0": "000000",  "1": "0000AA",  "2": "00AA00",  "3": "00AAAA",
    "4": "AA0000",  "5": "AA00AA",  "6": "FFAA00",  "7": "AAAAAA",
    "8": "555555",  "9": "5555FF",  "a": "55FF55",  "b": "55FFFF",
    "c": "FF5555",  "d": "FF55FF",  "e": "FFFF55",  "f": "FFFFFF",
}

COLOR_MAPPINGS_EX = {
    # 基岩版颜色代码(剔除重复)
    "g": "DDD605",  "h": "E3D4D1",  "i": "CECACA",  "j": "443A3B",
    "m": "971607",  "n": "B4684D",  "p": "DEB12D",  "q": "47A036",
    "s": "2CBAA8",  "t": "21497B",  "u": "9A5CC6",  "v": "EB7114",
    "w": "8CB3FF",

    # 你可以提交issue/PR来申领一个自己的颜色代码
    "C": "CB5CFE",
}
# fmt: on

STYLE_MAPPINGS = {
    "l": "1",  # 加粗
    "m": "9",  # 删除线
    "n": "4",  # 下划线
    "o": "3",  # 斜体
    "k": "6",  # 乱码:闪烁 (原先为隐藏(8))
    # r 的格式是 恢复默认 默认的颜色由函数传入的参数决定，因此留空
    # "r": "0",
}

CONTROL_CHARS: set[str] = set(
    chr(c)
    for c in [
        *range(0x00, 0x20),  # 基础C0控制字符
        0x7F,  # DEL删除字符
        *range(0x80, 0xA0),  # C1控制字符
        *range(0x200B, 0x2010),  # 零宽空格系列
        *range(0x202A, 0x202F),  # 双向文本控制字符
        0x2028,  # 行分隔符
        0x2029,  # 段落分隔符
        *range(0x2060, 0x206A),  # 格式控制字符
        0x061C,  # 阿拉伯语格式控制字符
        *range(0xFE00, 0xFE10),  # 变体选择符
        *range(0x0E0100, 0x0E01F0),  # 变体选择符补充
        *range(0x0E0000, 0x0E0080),  # 专用区/标签字符
    ]
)

PACKET_PATTERN_STRING = re.compile(
    r"""\[MOTD\](?P<motd>.*)\[/MOTD\]  # 捕获MOTD和端口号
        \[AD\](?P<ad>.*)\[/AD\]        # 以上两项必须出现
        (\[FML\](?P<fml>.*)\[/FML\])?  # 捕获FML，这一项可选""",
    re.VERBOSE,
)

PACKET_PATTERN_BYTES = re.compile(
rb"""
\[MOTD\](?P<motd>.*?)\[/MOTD\]
\[AD\](?P<ad>.*?)\[/AD\]
(\[FML\](?P<fml>.*?)\[/FML\])?
""".replace(b'\n', b'')
)

IPType: TypeAlias = Literal["ipv4/v8", "ipv4", "ipv8", "ipv6", "unknown"]


class ParsedPacket(NamedTuple):
    motd: str
    ad: str
    fml: str | None


def auto_decode_bytes(
    data: bytes,
    fallback_encodings: Sequence[str] = ("utf-8", "gbk"),
    allow_encodings: Sequence = (),
) -> tuple[str, str]:
    if not data:
        return "", "utf-8"
    result = from_bytes(data).best()

    if result and (not allow_encodings or result.encoding in allow_encodings):
        return result.output().decode("utf-8"), result.encoding
    for falledback_encoding in fallback_encodings:
        with suppress(UnicodeDecodeError):
            text = data.decode(falledback_encoding)
            return text, falledback_encoding

    return data.decode(
        fallback_encodings[0],
        errors="backslashreplace",
    ), fallback_encodings[0]


# 这个函数似乎并没有人用
def filter_ip(
    ip: str,
    iptype: IPType = "unknown",
) -> str:
    if iptype in {"ipv4/v8", "ipv4", "ipv8"}:
        achars = set("0123456789.")
    elif iptype == "ipv6":
        achars = set("0123456789abcdef:")
    else:
        achars = set("0123456789.abcdef:")

    return "".join(filter(lambda char: char in achars, ip))


def parse_mc_lanpacket(text: str) -> ParsedPacket:
    text_match = PACKET_PATTERN_STRING.match(text)
    if text_match is None:
        raise ValueError

    return ParsedPacket(**text_match.groupdict())


def parse_mc_style(
    text: str,
    pre_allocate_ex_bufsize: int = 256,
    *,
    enable_color: bool = True,
    enable_ex_color: bool = True,
    enable_true_color: bool = True,
    enable_style: bool = True,
    enable_reset: bool = True,
    always_hex_color: bool = True,
    using_gray_default: bool = False,
    auto_reset_ansi_back: bool = True,
    safe: bool = True,
) -> str:
    max_idx = len(text) - 1
    buf = io.StringIO()

    buf.seek(
        len(text)
        + (3 if auto_reset_ansi_back else 0)
        + int(max(0, pre_allocate_ex_bufsize))
    )  # 可见我也是为了最大兼容性煞费苦心
    buf.write("")  # 触发预分配空间
    buf.seek(0)

    GLOBAL_COLOR_MAPPINGS = (
        COLOR_MAPPINGS.copy()
        if always_hex_color
        else COLOR_MAPPINGS_ANSI.copy()
    )
    if always_hex_color:
        for key in GLOBAL_COLOR_MAPPINGS.keys():
            hexstr = GLOBAL_COLOR_MAPPINGS[key]
            r, g, b = (
                int(hexstr[:2], 16),
                int(hexstr[2:4], 16),
                int(hexstr[4:], 16),
            )
            GLOBAL_COLOR_MAPPINGS[key] = f"38;2;{r};{g};{b}"
    color_keys = set(GLOBAL_COLOR_MAPPINGS.keys()) if enable_color else set()
    ex_color_keys = set(COLOR_MAPPINGS_EX.keys()) if enable_ex_color else set()
    style_keys = set(STYLE_MAPPINGS.keys()) if enable_style else set()

    will_skipped_char_cnt = 0

    if using_gray_default:
        buf.write(
            f"\033[0;{GLOBAL_COLOR_MAPPINGS['7']}m"
        )  # 像原版客户端一样的默认灰色

    for idx, char in enumerate(text):
        if will_skipped_char_cnt > 0:
            will_skipped_char_cnt -= 1
            continue

        if char != "§" or idx + 1 > max_idx:
            if safe and char in CONTROL_CHARS:
                code = ord(char)
                buf.write(
                    f"\\x{code:02X}" if code <= 0xFF else f"\\u{code:08X}"
                )
            else:
                buf.write(char)
            continue

        next_char = text[idx + 1]
        if next_char in color_keys:
            buf.write(f"\033[0;{GLOBAL_COLOR_MAPPINGS[next_char]}m")
            will_skipped_char_cnt += 1
        elif next_char in style_keys:
            buf.write(f"\033[{STYLE_MAPPINGS[next_char]}m")
            will_skipped_char_cnt += 1
        elif next_char in ex_color_keys:
            hexstr = COLOR_MAPPINGS_EX[next_char]
            r, g, b = (
                int(hexstr[:2], 16),
                int(hexstr[2:4], 16),
                int(hexstr[4:], 16),
            )
            buf.write(f"\033[0;38;2;{r};{g};{b}m")
            will_skipped_char_cnt += 1
        elif next_char == "r" and enable_reset:
            buf.write(
                f"\033[0;{GLOBAL_COLOR_MAPPINGS['7']}m"
                if using_gray_default
                else "\033[0m"
            )
            will_skipped_char_cnt += 1
        elif enable_true_color and next_char == "x" and idx + 13 <= max_idx:
            stylestr = text[idx + 2 : idx + 14]
            hexstr = stylestr[1:13:2]  # 从1开始 直到12(包含)个字符 步长为2
            r, g, b = (
                int(hexstr[:2], 16),
                int(hexstr[2:4], 16),
                int(hexstr[4:], 16),
            )
            buf.write(f"\033[0;38;2;{r};{g};{b}m")
            will_skipped_char_cnt += 13
        else:
            if safe and char in CONTROL_CHARS:
                code = ord(char)
                buf.write(
                    f"\\x{code:02X}" if code <= 0xFF else f"\\u{code:08X}"
                )
            else:
                buf.write(char)

    if auto_reset_ansi_back:
        buf.write("\033[0m")  # 保底恢复颜色

    return buf.getvalue()
