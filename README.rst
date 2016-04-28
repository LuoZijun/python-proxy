Python Socks5 Proxy
========================

:Date: 04/28 2016

.. contents::

简介
------

一个基于Python写的Socks5代理脚本。


使用
------

.. code:: python

    ip, port = ("127.0.0.1", 1070)
    sock5    = Sock5(ip=ip, port=port)

    sock5.run()

依赖
-------

1.  select
2.  logging
