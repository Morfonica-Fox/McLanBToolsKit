import random


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
