from __future__ import annotations

import ctypes
import importlib
import io
import logging
import os
import socket
import struct
import subprocess
import sys
import threading
import time

from Lib.test.test_importlib.frozen.test_loader import deprecated

os.chdir(os.path.dirname(__file__))

LOG_LEVEL = logging.INFO


# [+] 开箱即用优化
def ensure_package(
    package_name, *, import_name=None, version=None, uninstall=False, reinstall=False
):
    if import_name is None:
        import_name = package_name
    if version:
        package_spec = f"{package_name}=={version}"
    else:
        package_spec = package_name

    try:
        if uninstall or reinstall:
            raise ImportError
        return importlib.import_module(import_name)
    except ImportError:
        print(f"未找到 {package_spec}.")
        print(f"正在安装 {package_spec} ...")
        try:
            if not uninstall:
                if reinstall:
                    subprocess.check_call(
                        [
                            sys.executable,
                            "-m",
                            "pip",
                            "install",
                            "--force-reinstall",
                            "--no-cache-dir",
                            package_spec,
                        ],
                        stderr=subprocess.STDOUT,
                    )
                else:
                    subprocess.check_call(
                        [
                            sys.executable,
                            "-m",
                            "pip",
                            "install",
                            "--user",
                            package_spec,
                        ],
                        stderr=subprocess.STDOUT,
                    )
            else:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "uninstall", package_spec],
                    stderr=subprocess.STDOUT,
                )
        except subprocess.CalledProcessError:
            if not uninstall:
                print(f"自动安装失败，请手动执行：pip install {package_spec}")
                sys.exit(1)
            else:
                pass
        return importlib.import_module(import_name)


# [+] 识别软件包
ensure_package("elevate")
ensure_package("rich")
ensure_package("colorama")
ensure_package("watchdog")
ensure_package("pydivert")

import colorama

# [Tip] ide补全, 可删除
import elevate

# [+] python 高版本无法使用

enable_rich = True
try:

    from rich.console import Console
    from rich.logging import RichHandler

except ImportError:
    enable_rich = False

import pydivert
from watchdog.events import FileSystemEventHandler

# [Tip] 上方 ensure 的时候以导入 watchdog
from watchdog.observers import Observer

from mc_lanb_advtools import *

# [+] 确保已有rich的情况下将 handler 替换
if enable_rich:
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(message)s",  # RichHandler 会自带时间和样式，只需输出消息
        handlers=[RichHandler(highlighter=None, markup=True)],  # 替换
    )

    logger = logging.getLogger(__name__)
else:
    logging.basicConfig(
        level=LOG_LEVEL,
        format="{%(asctime)s - %(name)s} %(filename)s[line:%(lineno)d][%(threadName)s][%(levelname)s] %(message)s",
    )
    logger = logging.getLogger(__name__)

import mc_lanb_cond

# [=] 将 keeped 改为 kept
mc_lanb_cond.kept_data = {}


def install_whl_package(whl_filename: str):
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


def enable_vt_console():
    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32
        h = kernel32.GetStdHandle(-11)
        if h == -1:
            return False
        mode = ctypes.c_uint()
        if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if not kernel32.SetConsoleMode(h, new_mode):
            return False
        return True
    # [+] 增加 else 分支
    else:
        return False


# [+] 增加 判断返回值
if not enable_vt_console():
    logging.warning("Vt console not enabled")


def mc_lan_multicast_hold(
    mc_mcast_group: str = "224.0.2.60", mc_mcast_port: int = 4445
):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except:
        pass

    sock.bind(("0.0.0.0", mc_mcast_port))

    mreq = struct.pack("4sl", socket.inet_aton(mc_mcast_group), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        try:
            sock.recvfrom(1024)
        except socket.error:
            pass


def start_mcast_hold_daemon():
    t = threading.Thread(target=mc_lan_multicast_hold, daemon=True)
    t.start()


start_mcast_hold_daemon()


def reload():
    global mc_lanb_cond
    mc_lanb_cond.will_update(time.time())
    mc_lanb_cond = importlib.reload(mc_lanb_cond)
    mc_lanb_cond.on_updated(time.time())


reload()


class CodeEventHandler(FileSystemEventHandler):
    def __init__(
        self,
    ):
        self.last_updated_time = -1

    def on_modified_bak(self, event):
        if time.time() - self.last_updated_time < 0.1:
            return
        fpath, encoding, clear_namespace = self._condition.binder
        if event.src_path != fpath:
            return
        with open(fpath, "r", encoding=encoding) as f:
            self._condition.set_code(f.read(), clear_namespace=clear_namespace)
        self.last_updated_time = time.time()

    def on_modified(self, event):
        if time.time() - self.last_updated_time < 0.1:
            return
        reload()


filter_str = f"udp and udp.DstPort == 4445"
w: pydivert.WinDivert | None = None


def main():
    logger.info(f"将使用指定的 WFL 过滤器启动UDP局域网广播包捕获: {filter_str}")

    obs = Observer()
    hdr = CodeEventHandler()
    obs.schedule(hdr, os.path.dirname(__file__), recursive=False)
    obs.start()

    reload()
    global w
    w = pydivert.WinDivert(filter_str)
    w.open()
    try:
        while True:
            pkt: pydivert.Packet = w.recv()
            try:
                mc_lanb_cond.handler(pkt, w, logger, enable_rich)
            except Exception as e:
                logging.error("发生错误!", exc_info=e)
                pass
    except PermissionError as e:
        logging.error("权限不足! 请使用管理员运行此脚本!", exc_info=e)
        close_WinDivert()
        exit(1)
    except KeyboardInterrupt:
        print("^C received, shutting down")
        close_WinDivert()
        exit(0)


def close_WinDivert():
    global w
    if w:
        w.close()
    logger.info("关闭 pydivert 完成")


if __name__ == "__main__":
    logger.info("请求管理员权限...")

    colorama.init()

    try:
        elevate.elevate(show_console=True, graphical=True)
        main()
    except KeyboardInterrupt:
        print("^C received, shutting down")
        close_WinDivert()
        exit(0)
    except SystemExit as e:
        close_WinDivert()
        sys.exit(e.code)
