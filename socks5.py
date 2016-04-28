#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os, sys, time
import socket, struct, select
import thread

import logging

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

"""


support_nmethod   = ['\x00','\x02','\x01']
support_version   = ['\x05']         
support_method    = ['\x00','\x01']
support_cmd       = ['\x01']
support_addr_type = ['\x01','\x03']
support_protocol  = ['HTTP']


HTTP_RESPONSE     = '''HTTP/1.1 200 OK\r
Server: Python-Socks5/0.1 (Ubuntu)\r
Content-Type: text/html\r
Content-Length: 89\r
Connection: close\r
\r
<html><title>Python Proxy Server</title><h1>This Is One Socks5 Proxy Server.</h1></html>
\r\n'''

class Forward:
    # forward handler
    def __init__(self, source=None, target=None):
        self.source = source
        self.target = target
    def start(self):
        fdset = [self.source, self.target]
        while True:
            r, w, e = select.select(fdset, [], [5]) 
            if self.source in r:
                buff = self.source.recv(9216)
                
                if not buff: break
                
                # logging.debug('forward request by client:')
                # for line in buff.split("\n"):
                #    print "\t%s" % repr(line)

                # logging.error('client request content forward to target fail.')
                self.target.send(buff)

            if self.target in r: 
                buff = self.target.recv(9216)
                
                if not buff: break

                # logging.debug('response back by remote:')
                # for line in buff.split("\n"):
                #     print "\t%s" % repr(line)

                # logging.error('Target response forward to client fail.')
                self.source.send(buff)
                

    def guess_protocol(self):
        pass

class Relay:
    ip         = ""
    port       = 0
    connection = None

    timeout    = 10

    def __init__(self, ip="", port=0):
        self.ip   = ip
        self.port = port
    def connect(self):
        conn      = socket.socket()
        conn.connect((self.ip, self.port))
        conn.settimeout(self.timeout)

        peer_addr       = conn.getpeername()[0]  #  -128 <= remote_peer_name <= 127
        peer_port       = conn.getpeername()[1]

        self.connection = conn

        return (peer_addr, struct.pack('!h',peer_port))
    def send(self, data):
        self.connection.send(data)
    def recv(self, number):
        self.connection.recv(number)

class Connection:
    ip         = ""
    port       = 0
    
    connection = None
    relay      = None

    timeout    = 10
    def __init__(self, connection=None, ip="", port=0):
        self.connection = connection
        self.ip         = ip
        self.port       = port
        # config
        self.connection.settimeout(self.timeout)
    def start(self):
        # 握手
        status = self.shake_hands()
        if status == False:
            return self.connection.close()

        # 处理转发请求
        status = self.process_request()
        if status == False:
            return self.connection.close()

        # 执行转发任务
        forward   =  Forward(source=self.connection, target=self.relay.connection)
        try:
            forward.start()
        except:
            logging.info('unknow error.')

        logging.info('forward done.')

        # End.
        self.connection.close()
        self.relay.connection.close()

    def process_request(self):
        # ATYP: DST.ADR.TYPE ( '\x01': IPv4, '\x03': DOMAINNAME, '\x04': IPv6 )
        (ver, cmd, rsv, atyp) = tuple(self.connection.recv(4))
        # DST.ADR 长度必须小于或大于 127-byte
        dst_addr_size     = self.connection.recv(1)
        (size, )          = struct.unpack('b', dst_addr_size)
        
        dst_addr  = self.connection.recv( size )
        dst_port  = self.connection.recv(2)
        (port, )  = struct.unpack('!h',  dst_port)
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
        if ver not in support_version:
            rep_code = "\x02"
        if cmd not in support_cmd:
            rep_code = "\x07"
        if atyp not in support_addr_type:
            rep_code = "\x08"

        # Server bound address or client's.
        bnd_addr_size = dst_addr_size
        bnd_addr      = dst_addr
        bnd_port      = dst_port

        if rep_code == "":
            # Make Relay Connection.
            self.relay= Relay(ip=dst_addr, port=port )
            try:
                bnd                  = self.relay.connect()
                (bnd_addr, bnd_port) = bnd
                bnd_addr_size        = struct.pack('b', len(bnd_addr))
                rep_code             = "\x00" # succeeded
            except:
                # general SOCKS server failure
                rep_code= "\x01"

        message = ( ver, rep_code, rsv, atyp, bnd_addr_size, bnd_addr, bnd_port )
        
        self.connection.send("".join(message))
        return True

    def shake_hands(self):
        buff = self.connection.recv(3)
        if buff == "GET":
            # close connection.
            self.connection.send(HTTP_RESPONSE)
            return False
        elif buff[0] in support_version and buff[1] in support_nmethod and buff[2] in support_method:
            self.connection.send('\x05\x00')
            return True
        else:
            self.connection.send('\x05\xFF')
            return False

class Sock5:
    ip      = "127.0.0.1"
    port    = 1070
    service = None

    def __init__(self, ip="127.0.0.1", port=1070):
        self.ip   = ip
        self.port = port
    def run(self):
        
        logging.info("Python proxy run on %s:%d ..." %(self.ip, self.port))

        self.service = socket.socket()
        self.service.bind((self.ip, self.port))
        self.service.listen(10)

        # run forever
        self.loop()

    def process(self, conn, addr):
        host = "%s: %d" %(addr[0], addr[1])

        logging.info('connection (%s) begin ...' % host )
        
        connection = Connection(connection=conn, ip=addr[0], port=addr[1])
        try:
            connection.start()
        except socket.timeout:
            logging.warning('connection(%s) timeout.' % host)

        logging.info('connection (%s) close.' % host )

    def loop(self):
        while True:
            conn, addr = self.service.accept()
            try:
                thread.start_new_thread(self.process, (conn, addr, ) )
            except:
                logging.debug("thread can't start ...")


if __name__ == '__main__':
    ip   = "127.0.0.1"
    port = 1070
    sock5 = Sock5(ip=ip, port=port)
    sock5.run()

