import socket
import threading
import time
from typing import Any, Callable, TypedDict

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

# import os
# os.chdir(os.path.dirname(os.path.abspath(__file__)))


def send_multicast(
    group: str,
    port: int,
    message: str,
    ttl: int = 255,
    local_interface: str = "0.0.0.0",
):
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        socket.IPPROTO_UDP,
    ) as sock:
        if local_interface == "0.0.0.0":
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_TTL,
                ttl,
            )
        else:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(local_interface),
            )

        data = message.encode("utf-8")
        sock.sendto(data, (group, port))


def load_servers_from_conf(retry_times: int = 5):
    global msc
    if retry_times <= 0:
        raise ImportError("配置文件无法加载!")
    try:
        msc = {}
        with open("mc_servers_config.py", "r", encoding="utf-8") as f:  # noqa: PTH123
            exec(f.read(), msc, msc)
        print("[+] 加载配置文件完成!")
    except Exception:
        load_servers_from_conf(retry_times - 1)


class ConfFlushHandler(FileSystemEventHandler):
    def on_modified(self, event: FileSystemEvent):  # noqa: ARG002
        load_servers_from_conf()
        start_broadcast_worker()


def start_conf_flush_monitor() -> tuple[ConfFlushHandler, BaseObserver]:
    observer = Observer()
    handler = ConfFlushHandler()
    observer.schedule(handler, ".", recursive=False)
    observer.start()
    print("[+] 开始监控配置文件修改...")
    return handler, observer


def stop_conf_flush_monitor(observer: BaseObserver):
    observer.stop()
    observer.join()


class ConfigServerData(TypedDict):
    port: Any
    motd: Any
    send_delay: float | Callable[..., float]


def broadcast_worker(called_server: ConfigServerData | Callable[..., ConfigServerData]):
    global working

    while working:
        start_time = time.time()

        server = called_server() if callable(called_server) else called_server

        server_port = server["port"]
        server_motd = server["motd"]
        send_delay = server["send_delay"]
        if callable(send_delay):
            send_delay = send_delay()

        send_multicast(
            MULTICAST_GROUP,
            MULTICAST_PORT,
            f"[MOTD]{server_motd}[/MOTD][AD]{server_port}[/AD]",
        )
        while (time.time() - start_time < send_delay) and working:
            time.sleep(min(max(time.time() - start_time - send_delay, 0), 0.01))


def start_broadcast_worker():
    global working
    global msc

    working = False
    for worker in worker_threads:
        worker.join()
    worker_threads.clear()  # 停止之前的工作线程

    working = True
    for server in msc["servers"]:
        worker_thread = threading.Thread(
            target=broadcast_worker,
            args=(server,),
            daemon=True,
        )
        worker_thread.start()  # 启动新的工作线程
        worker_threads.append(worker_thread)  # 将工作线程添加到列表中


def delay_reload_config():
    while delay_reloading:
        load_servers_from_conf()
        start_broadcast_worker()
        time.sleep(5)


working = False

delay_reloading = True

load_servers_from_conf()

if __name__ == "__main__":
    print(
        "\033[1;38;2;173;56;232mMinecraft LanB Project"
        "\033[0m / "
        "\033[1;38;2;151;255;177mUDP Server Broadcaster"
        "\033[0m 1.2.0-dev Running"
    )

    worker_threads: list[threading.Thread] = []

    MULTICAST_GROUP = "224.0.2.60"
    MULTICAST_PORT = 4445

    hdl, obs = start_conf_flush_monitor()
    try:
        # reloader = threading.Thread(target=delay_reload_config, daemon=True)
        # reloader.start()
        start_broadcast_worker()
        while True:
            time.sleep(0.01)
    except KeyboardInterrupt:
        pass
    finally:
        stop_conf_flush_monitor(obs)
        # delay_reloading = False
