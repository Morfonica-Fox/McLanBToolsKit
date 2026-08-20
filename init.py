#Copyright (c) [2026] [Morfonica_Fox]
#[McLanBToolsKit] is licensed under Mulan PubL v2.
#You can use this software according to the terms and conditions of the Mulan PubL v2.
#You may obtain a copy of Mulan PubL v2 at:
#         http://license.coscl.org.cn/MulanPubL-2.0
#THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
#EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
#MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
#See the Mulan PubL v2 for more details.

import subprocess
import sys

def install_from_requirements(path="requirements.txt"):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", path])

__doc__ = '''\
运行本脚本将会自动安装所有依赖!
CPython 3.11/3.12 已测试全功能没问题
不要用 CPython 3.14+ ! pydivert不兼容
PyPy 3.11仅可以用服务器广播器/广播防火墙 暂时不能用最热服务器扫描器
'''

import subprocess
import sys


def install_from_requirements(path="requirements.txt"):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", path])  # noqa: S603


if __name__ == "__main__":
    print(__doc__)
    input("按回车键继续... ")
    install_from_requirements()
