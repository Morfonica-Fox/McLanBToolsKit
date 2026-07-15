### Minecraft LanB Tools Kit (原名 Minecraft LanB Project)
基于python的Minecraft LanBroadcast工具包

主要有2个工具:
  Minecraft LanBroadcast Firewall: 防火墙 入口文件对应 mc_lanb_firewall.py
  Minecraft LanBroadcaster: 广播器 入口文件对应 mc_server_udp_broadcast.py

防火墙:
  多文件架构 单进程
  保存对 mc_lanb_cond.py 的更改后自动热重载代码与依赖(重载依赖由 mc_lanb_cond.py 完成) 内置已足够防御 pp1.5s/ppm 过高的刷屏攻击 如果你要自定义直接修改即可
    Note: 由于是作者自用 所以代码中有些奇怪的数据是正常的
  默认控制台输出内容: (下文 pps 统一指 pp1.5s 即 每1.5秒的包速率)
    日期(YYYY-MM-DD) 时间(HH:MM:SS) 服务器pps 服务器ppm IPpps IPppm 源IP (箭头) 目标IP 服务器端口(由报文的AD字段决定 并非报文源端口) 报文编码 MOTD内容(已格式化)
  所需依赖:
    python 3.7+
    pydivert 2.1.0+ (PyPy 兼容且推荐)
    charset-normalizer 2.0.0+
    watchdog 6.0.0+
  已知稳定环境:
    1.
      pypy 3.11
      pydivert 2.1.0
      charset-normalizer 3.4.7
      watchdog 6.0.0
    2.
      cpython 3.11
      pydivert 3.1.2
      charset-normalizer 3.4.7
      watchdog 6.0.0

广播器:
  (就不写喵 应该都能读懂...对吧? 读不懂的开个issue吧)

正在开发:
  GUI界面
  防火墙计时器 - 时间对齐统计
  防火墙拦截器 - 延迟发包
  pyinstaller打包exe开箱即用/自动部署环境