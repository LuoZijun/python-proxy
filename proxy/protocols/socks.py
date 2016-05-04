#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os, sys, time
import socket, struct, select
import logging

from   proxy.utils import DummySocket
from   urlparse    import urlparse

reload(sys)
sys.setdefaultencoding('utf8')

logging.basicConfig(
    # filename ='proxy.log',
    format  = '%(asctime)s %(message)s',
    datefmt = '%Y-%m-%d %H:%M:%S',
    level   = logging.DEBUG
)


"""
RFC:
    socks5: https://tools.ietf.org/html/rfc1928
    socks5 with authentication: http://www.ietf.org/rfc/rfc1929.txt

通讯认证方法(METHODS):
    X'00'    无验证需求
    X'01'    通用安全服务应用程序接口（GSSAPI）
    X'02'    用户名/密码(USERNAME/PASSWORD) 
    X'03'    至 X'7F' IANA 分配(IANA ASSIGNED) 
    X'80'    至 X'FE' 私有方法
    X'FF'    无可接受方法(NO ACCEPTABLE METHODS) 

转发请求(Requests):
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

连接类型(CMD):
    CONNECT      : X'01'    建立连接
    BIND         : X'02'    绑定
    UDP ASSOCIATE: X'03'    UDP连接

地址类型(ATYP):
    IP V4 address: X'01'    IP(IPv4)
    DOMAINNAME   : X'03'    域名
    IP V6 address: X'04'    IP(IPv6)


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


"""


# support_nmethod   = ['\x00','\x02','\x01']
# support_version   = ['\x05']         
# support_method    = ['\x00','\x01']
# support_cmd       = ['\x01']
# support_addr_type = ['\x01','\x03']
# support_protocol  = ['HTTP']

# HTTP_METHODS      = ['GET', 'HEAD', 'PUT', 'DELETE', 'POST', 'CONNECT', 'OPTIONS', 'TRACE']

HTTP_RESPONSE     = '''HTTP/1.1 406 Not Acceptable\r
Server: Python-Socks5/0.1 (Ubuntu)\r
Content-Type: text/html\r
Content-Length: 153\r
Connection: close\r
\r
<html>
    <head>
        <title>Python Proxy Server</title>
    </head>
    <body>
        <h1>this is one socks5 proxy server.</h1>
    </body>
</html>
\r\n'''

class Relay:
    timeout = 10
    def __init__(self, host="", port=0):
        self.host = host
        self.port = port

    def pipe(self, source=None):
        fdset = [source, self.connection]
        while True:
            r, w, e = select.select(fdset, [], [5]) 
            if source in r:
                buff = source.recv(9216)
                
                if not buff: break
                
                # logging.debug('forward request by client:')
                # for line in buff.split("\n"):
                #    print "\t%s" % repr(line)
                
                # logging.error('client request content forward to target fail.')
                self.connection.send(buff)

            if self.connection in r: 
                buff = self.connection.recv(9216)
                
                if not buff: break

                # logging.debug('response back by remote:')
                # for line in buff.split("\n"):
                #     print "\t%s" % repr(line)

                # logging.error('Target response forward to client fail.')
                source.send(buff)

    def connect(self):
        logging.info('[Socks] Relay connect to %s:%d ... ' % (self.host, self.port) )
        conn      = socket.socket()
        conn.connect((self.host, self.port))
        conn.settimeout(self.timeout)
        peer_addr       = conn.getpeername()[0]  #  -128 <= remote_peer_name <= 127
        peer_port       = conn.getpeername()[1]

        self.connection = conn

        # self.connection.setblocking(0)
        return (peer_addr, struct.pack('!h',peer_port))

    def send(self, data):
        self.connection.send(data)

    def recv(self, number):
        self.connection.recv(number)


class Socks4:
    def __init__(self, buff="", session=None, host="", port=0):
        self.host    = host
        self.port    = port
        self.buff    = buff
        self.session = session

    def handle(self):
        # not support.
        logging.info('[Socks] this version of the socks protocol only support Version 5.')


class Socks5:
    def __init__(self, buff="", session=None, host="", port=0):
        self.host    = host
        self.port    = port
        self.buff    = buff
        self.session = session

    def handle(self):
        # 处理转发请求
        status = self.process_request()
        if status == False: return False

        # 执行转发任务
        try:
            self.relay.pipe(source=self.session)
        except Exception as e:
            logging.info('[Relay] make pipe fail.')
            logging.info(e)

    def process_request(self):
        # ATYP: DST.ADR.TYPE ( '\x01': IPv4, '\x03': DOMAINNAME, '\x04': IPv6 )
        (ver, cmd, rsv, atyp) = tuple(self.session.recv(4))

        # DST.ADR 长度必须小于或大于 127-byte
        dst_addr_size     = self.session.recv(1)
        # print "DST.ADDR Size(Hex): ", repr(dst_addr_size)
        (size, )          = struct.unpack('b', dst_addr_size)
        # print "DST.ADDR Size(Int): ", repr(size)
        # DEBUG: 已知问题，curl 在开启 socks5 模式下的请求，DST.ADDR 地址的解析有问题！
        dst_addr,  = struct.unpack("!%ds"%size, self.session.recv(size))

        # print "DST.ADDR (Raw): ", repr(dst_addr)

        dst_port  = self.session.recv(2)
        # print "DST.ADDR Port (Hex): ", repr(dst_port)

        (port, )  = struct.unpack('!h',  dst_port)
        # print "DST.ADDR Port (Int): ", repr(port)

        # Replies
        """
            o  VER    protocol version: X'05'
            o  REP    Reply field:
                o  X'00' succeeded
                o  X'01' general SOCKS server failure
                o  X'02' connection not allowed by ruleset
                o  X'03' Network unreachable
                o  X'04' Host unreachable
                o  X'05' Connection refused
                o  X'06' TTL expired
                o  X'07' Command not supported
                o  X'08' Address type not supported
                o  X'09' to X'FF' unassigned
            o  RSV    RESERVED
            o  ATYP   address type of following address
                o  IP V4 address: X'01'
                o  DOMAINNAME: X'03'
                o  IP V6 address: X'04'
            o  BND.ADDR       server bound address
            o  BND.PORT       server bound port in network octet order
        """

        rep_code     = ""
        if ver != "\x05":
            rep_code = "\x02"
        if cmd != "\x01":
            rep_code = "\x07"
        if atyp not in ['\x01','\x03']:
            rep_code = "\x08"

        # Server bound address or client's.
        bnd_addr_size = dst_addr_size
        bnd_addr      = dst_addr
        bnd_port      = dst_port
        if rep_code == "":
            # Make Relay Connection.
            self.relay               = Relay(host=dst_addr, port=port )
            try:
                bnd                  = self.relay.connect()
                (bnd_addr, bnd_port) = bnd
                bnd_addr_size        = struct.pack('b', len(bnd_addr))
                rep_code             = "\x00" # succeeded
            except:
                # general SOCKS server failure
                logging.info('[Socks] Relay connect to %s:%d failure' %(dst_addr, port) )
                rep_code= "\x01"

        message = ( ver, rep_code, rsv, atyp, bnd_addr_size, bnd_addr, bnd_port )

        self.session.send("".join(message))
        if rep_code == "\x00":
            return True
        else:
            return False


class Socks:
    def __init__(self, buff="", session=None, host="", port=0):
        self.host    = host
        self.port    = port
        self.buff    = buff
        self.session = session
    def handle(self):
        self.shake_hands()
    def shake_hands(self):
        """
        Request:
           +----+----------+----------+
           |VER | NMETHODS | METHODS  |
           +----+----------+----------+
           | 1  |    1     | 1 to 255 |
           +----+----------+----------+
        Response:
            +----+--------+
            |VER | METHOD |
            +----+--------+
            | 1  |   1    |
            +----+--------+
            回复结尾为0xFF，表示服务器实现该客户端请求的方法（Method） 
        """
        """
            support_nmethod   = ['\x00','\x02','\x01']
            support_version   = ['\x05']         
            support_method    = ['\x00','\x01']
            support_cmd       = ['\x01']
            support_addr_type = ['\x01','\x03']
            support_protocol  = ['HTTP']
        """
        # 0x05 0x02 0x00 0x01
        # version: 0x05 nmethods: 0x02 methods: 0x00, 0x01
        fd                = DummySocket(buff=self.buff, connection=self.session)
        version, nmethods = struct.unpack("!bb", fd.recv(2))
        methods           = fd.recv( nmethods )
        
        # print repr(version), repr(nmethods), repr(methods)

        if version   == 0x04:
            self.session.send('\x05\x00')
            socks    = Socks4(session=self.session)
            socks.handle()
        elif version == 0x05:
            self.session.send('\x05\x00')
            logging.info('[Socks] socks protocol version is 0x05, method is 0x00')
            socks    = Socks5(session=self.session)
            socks.handle()
        else:
            logging.info('[Socks] socks protocol version is 0x05')
            self.session.send('\x05\xFF')

