import subprocess
import sys

def install_from_requirements(path="requirements.txt"):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", path])

prompt = '''\
运行本脚本将会自动安装所有依赖!
CPython 3.11/3.12 已测试全功能没问题
PyPy 3.11仅可以用服务器广播器/广播防火墙 暂时不能用最热服务器扫描器
'''

if __name__ == "__main__":
    print(prompt)
    input("按回车键继续... ")
    install_from_requirements()
