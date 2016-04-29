#!/usr/bin/env python
#-*- coding:utf-8 -*-

import socket, select
import struct, logging


class Relay:
    def __init__(self):
        pass

"""
HTTP connect 请求为建立 TCP 隧道请求，隧道建立完毕需要返回一条通知讯息:
    
    'HTTP/1.1 200 Connection Established\r\n\r\n'

然后类似Socks，通过管道（Pipe）中继两端数据即可。

"""


class Http:
    def __init__(self, buff="", session=None, host="", port=0):
        self.session = session
        self.host    = host
        self.port    = port
        self.buff    = buff
    def start(self):
        pass



