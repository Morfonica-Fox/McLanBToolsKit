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

import ctypes
import importlib
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import NoReturn

import pydivert
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

script_dir = Path(__file__).parent.resolve() # 支持Embedding版本Python! 
sys.path.insert(0, str(script_dir)) # Embedding版Python默认不从脚本所在目录导入库 所以要加这个
import mc_lanb_cond
from mc_lanb_advtools import *

ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
mc_lanb_cond.kept_data = {}

def install_whl_package(whl_filename: str) -> bool:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    whl_path = os.path.join(current_dir, whl_filename)
    if not os.path.exists(whl_path):
        return False

    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", whl_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def enable_vt_console() -> bool:
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32
        h = kernel32.GetStdHandle(-11)
        if h == -1:
            return False
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return False

        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return not kernel32.SetConsoleMode(h, new_mode)


already_holded_multicast = threading.Event()
def mc_lan_multicast_hold(
    mc_mcast_group: str = "224.0.2.60",
    mc_mcast_port: int = 4445,
    # https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping#Ping_via_LAN_(Open_to_LAN_in_Singleplayer)
) -> NoReturn:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", mc_mcast_port))

    mreq = struct.pack(
        "4sl", socket.inet_aton(mc_mcast_group), socket.INADDR_ANY
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    already_holded_multicast.set()  
    
    while True:
        with suppress(OSError):
            sock.recvfrom(1024)


def start_mcast_hold_daemon():
    t = threading.Thread(target=mc_lan_multicast_hold, daemon=True)
    t.start()


def reload():
    global mc_lanb_cond
    original_kept_data = mc_lanb_cond.kept_data
    mc_lanb_cond.will_update(time.time())
    mc_lanb_cond = importlib.reload(mc_lanb_cond)
    mc_lanb_cond.kept_data = original_kept_data
    mc_lanb_cond.on_updated(time.time())
    # cb虽然但是不要乱动命名空间注入啊 或者调试一下:( 不调试就提交是不好的习惯


class CodeEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_updated_time = -1

    def on_modified(self, event):  # noqa: ARG002
        if time.time() - self.last_updated_time < 0.1: # ? 说的啥 noqa是什么 ARG002又是
            return
        reload()


def main():
    filter_str = "inbound and udp and udp.DstPort == 4445"
    print(
        "\033[0;1;33m" + "将使用指定的 WFL 过滤器启动UDP局域网广播包捕获: ",
        filter_str,
        end="\033[0m\n",
    )

    obs = Observer()
    hdr = CodeEventHandler()
    obs.schedule(hdr, os.path.dirname(__file__), recursive=False)
    obs.start()

    reload()

    with pydivert.WinDivert(filter_str) as w:
        while True:
            pkt: pydivert.Packet = w.recv()
            # with suppress(Exception):
            mc_lanb_cond.handler(pkt, w)


enable_vt_console()
if __name__ == "__main__":
    start_mcast_hold_daemon()
    already_holded_multicast.wait()
    main()
