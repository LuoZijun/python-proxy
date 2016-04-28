#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os, sys, time
import socket, struct, select
import thread, logging

from urlparse import urlparse

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

HTTP_METHODS      = ['GET', 'HEAD', 'PUT', 'DELETE', 'POST', 'CONNECT', 'OPTIONS', 'TRACE']

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
        # self.connection.setblocking(0)
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

    timeout    = 30
    def __init__(self, connection=None, ip="", port=0):
        self.connection = connection
        self.ip         = ip
        self.port       = port
        # config
        self.connection.settimeout(self.timeout)
    def close(self):
        self.connection.close()
        try:
            self.relay.connection.close()
        except:
            pass

    def start(self):
        # 握手
        status = self.shake_hands()
        if status == False or status == None:
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
        self.close()

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
    def read_http_request(self, conn):
        buff = ""
        while True:
            char = conn.recv(4096)
            if not char: break
            buff += char
            if "\r\n\r\n" in buff:
                # http header 读取完毕
                http_content = buff.split("\r\n\r\n")
                http_header  = http_content[0]
                if len(http_content) > 1:
                    del http_content[0]
                    http_body = "\r\n\r\n".join(http_content)
                else:
                    http_body = ""

                headers = http_header.split("\r\n")[1:]
                for h in headers:
                    k, v= h.split(": ")

                    if k.lower() == 'content-length':
                        limit_size = int(v) - len(http_body)
                        tmp        = conn.recv(limit_size)
                        buff      += tmp
                        http_body += tmp
                break
            else:
                if len(buff) > 2*1024*1024:
                    return ""
        return buff

    def process_http_request(self, buff=""):
        
        status   = None
        host     = ""
        port     = 80
        location = ""

        num      = 1
        while True:
            char = self.connection.recv(num)
            if not char: break

            buff += char

            if num == 1 and char == "\r":
                _tmp = buff.split(" ")
                if len(_tmp) < 2:
                    self.connection.send('HTTP/1.1 400 Bad Request')
                    status = False
                    break

                url = _tmp[1]
                if url.startswith("http://") == False and url.startswith("https://") == False:
                    url = "scheme://" + url
                result  = urlparse(url)
                if result.netloc == "":
                    status = self.process_http_request_without_host()
                    break

                host     = result.netloc.split(":")[0]
                if ":" in result.netloc:
                    try:
                        port = int(result.netloc.split(":")[1])
                    except:
                        pass

                location     = result.path
                if result.query:
                    location = "?".join((location, result.query))
                if result.fragment:
                    location = "#".join((location, result.fragment))

                num      = 4096
            if "\r\n\r\n" in buff:
                # http header 读取完毕
                http_content = buff.split("\r\n\r\n")
                http_header  = http_content[0]
                if len(http_content) > 1:
                    del http_content[0]
                    http_body = "\r\n\r\n".join(http_content)
                else:
                    http_body = ""

                headers = http_header.split("\r\n")[1:]
                for h in headers:
                    k, v= h.split(": ")

                    if k.lower() == 'content-length':
                        limit_size = int(v) - len(http_body)
                        tmp        = self.connection.recv(limit_size)
                        buff      += tmp
                        http_body += tmp
                break
            else:
                if len(buff) > 2*1024*1024:
                    return None
        logging.debug('[HTTP Proxy]: http request %s:%d:' %(host, port) )
        for line in buff.split("\n"):
            print "\t%s" % repr(line)

        logging.debug('[Status]: %s' %(str(status)))

        if status != None:
            return status

        lines   = buff.split("\r\n")
        _tmp    = lines[0].split(" ")
        _tmp[1] = location
        lines[0]= " ".join(_tmp)
        del _tmp

        # HTTP Proxy
        self.relay = Relay(ip=host, port=port )
        # Http response
        response   = ""
        # try:
        self.relay.connect()

        logging.debug('[HTTP Proxy]: http request forward:')
        for line in lines:
            print "\t%s" % repr(line)
        self.relay.connection.send("\r\n".join(lines))
        response = self.read_http_request(self.relay.connection)

        # except Exception as e:
        #     # self.connection.close()
        #     logging.error('[HTTP Proxy]: http request forward fail.')
        #     print e
        #     return False

        logging.debug('[HTTP Proxy]: http response:')
        for line in response.split("\n"):
            print "\t%s" % repr(line)

        self.connection.send(response)
        return None

    def process_http_request_without_host(self):
        self.connection.send(HTTP_RESPONSE)
        return False

    def shake_hands(self):
        buff = self.connection.recv(10)
        if buff.split(" ")[0] in HTTP_METHODS:
            # HTTP Request
            return self.process_http_request(buff=buff)

        # data = self.connection.recv(4096)
        # buff = self.connection.recv(3)
        buff = buff[0:3]

        if buff[0] in support_version and buff[1] in support_nmethod and buff[2] in support_method:
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
        self.service.listen(50)

        # run forever
        try:
            self.loop()
        except (KeyboardInterrupt, SystemExit):
            logging.info('server shutdown ...')
            self.service.close()

    def process(self, conn, addr):
        host = "%s: %d" %(addr[0], addr[1])

        logging.info('connection (%s) begin ...' % host )
        
        connection = Connection(connection=conn, ip=addr[0], port=addr[1])
        try:
            connection.start()
        except socket.timeout:
            logging.warning('connection(%s) timeout.' % host)
        except KeyboardInterrupt:
            conn.close()
            raise KeyboardInterrupt

        logging.info('connection (%s) close.' % host )

    def loop(self):
        while True:
            conn, addr = self.service.accept()
            try:
                thread.start_new_thread(self.process, (conn, addr, ) )
            except:
                logging.debug("thread can't start ...")


if __name__ == '__main__':
    ip   = "0.0.0.0"
    port = 1070
    sock5 = Sock5(ip=ip, port=port)
    sock5.run()

