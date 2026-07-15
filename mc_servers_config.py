import psutil
import random

def get_port_owner(port: int):
    for conn in psutil.net_connections(kind='tcp'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
            pid = conn.pid
            if pid:
                proc = psutil.Process(pid)
                return {'pid': pid, 'name': proc.name(), 'cmdline': proc.cmdline()}
    return None

def demo_server():
    server = {'motd': 'demo~', 'port': -1, 'delay': random.randint(1, 2)} # 每次都走调用 每次都是随机!
    return server

servers = [
    demo_server,  
]

# 猜猜为什么不用json了呢 解码它给你答案: (utf-8编码)
# SlNPTumZkOWItuWkquWkmuS6hi4uLiDmr5TlpoLovazkuYnnrKYg5q+U5aaC5byV5Y+3IOiAjOWGmeaIkHB56ISa5pys5Y+v5Lul55u05o6l55SocHnor63ms5Ug6L+Y5Y+v5Lul5a6e546w5Yqo5oCBbW90ZOWRog==