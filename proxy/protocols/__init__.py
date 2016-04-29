#!/usr/bin/env python
#-*- coding:utf-8 -*-

import ftp, http, socks, ssl


def guess_protocol(connection):
    buff = connection.recv(10)
    _r   = filter(lambda method: buff.startswith(method) , http.Methods.__methods__)
    if len(_r) > 0:
    	return (buff, 'http')
    elif buff.startswith("\x05") or buff.startswith("\x04"):
    	return (buff, 'socks')
    else:
    	return (buff, 'unknow')


