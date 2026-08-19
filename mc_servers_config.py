import psutil
import random


# 这个函数没有一个地方在调用 -- Cbscfe
def get_port_owner(port: int):
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
            pid = conn.pid
            if pid:
                proc = psutil.Process(pid)
                return {
                    "pid": pid,
                    "name": proc.name(),
                    "cmdline": proc.cmdline(),
                }
    return None


def demo_server():
    server = {
        "motd": "demo~",
        "port": "test",
        "send_delay": random.random() + 1,  # 每次都走调用 每次都是随机!
    }
    return server


servers = [
    demo_server,
]
