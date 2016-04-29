Python Socks5 Proxy
========================

:Date: 04/28 2016

.. contents::

简介
------

一个基于Python写的Socks5代理脚本。


使用
------

直接使用：

.. code:: bash

    git clone https://github.com/LuoZijun/python-proxy
    cd python-proxy
    python sock5.py

.. image:: assets/socks5.config.png


然后在你的浏览器当中的网络设置里，填上 代理地址： `127.0.0.1`，端口：`1070`。

最后勾上 `SOCKS 5` 和 `远程DNS`选项。

.. image:: assets/socks5.png


在你的代码当中引用：

.. code:: python

    ip, port = ("127.0.0.1", 1070)
    sock5    = Sock5(ip=ip, port=port)

    sock5.run()


依赖
-------

1.  select
2.  logging


不同软件对Socks协议的实现差异
------------------------------

1.  `curl` 软件的 socks5 协议于 `Firefox` 实现不一致。


RFC1928对于 SOCKS Request 的协议定义:


+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

即：

    0x05 0x01 0x00 0x01 0x09 www.t.com 0x50

其中，`0x09` 这个位是 `DST.ADDR` 地址变量的长度，但是在 `curl` 实现的协议里面似乎不是这样。地址得不到正确解析。

 
