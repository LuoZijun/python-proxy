#!/usr/bin/env python
#-*- coding:utf-8 -*-
#author:luozijun
#email:gnulinux@126.com

# Socks5 RFC : https://tools.ietf.org/html/rfc1928

"""


通讯认证方法(METHODS):
    X'00'    无验证需求
    X'01'    通用安全服务应用程序接口（GSSAPI）
    X'02'    用户名/密码(USERNAME/PASSWORD) 
    X'03'    至 X'7F' IANA 分配(IANA ASSIGNED) 
    X'80'    至 X'FE' 私人方法保留(RESERVED FOR PRIVATE METHODS) 
    X'FF'    无可接受方法(NO ACCEPTABLE METHODS) 

转发请求(Requests):
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

连接类型(CMD):
    CONNECT X'01'                建立连接
    BIND X'02'                         绑定
    UDP ASSOCIATE X'03'     UDP连接

地址类型(ATYP):
    IP V4 address: X'01'                IP(IPv4)
    DOMAINNAME: X'03'             域名
    IP V6 address: X'04'                IP(IPv6)

建立回复(Replaies):
      +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
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

Fields marked RESERVED (RSV) must be set to X'00'.
标志RESERVED(RSV)的地方必须设置为X'00'。
如果被选中的方法包括有认证目的封装，完整性和/或机密性的检查，则回应就被封装在方法选择的封装套中。 
"""

import os,sys,time
import socket,struct
import re


support_nmethod = ['\x00','\x02']     # 目前认证方法只支持(无验证/用户名密码/), 不支持GSSAPI,IANA ASSIGNED,RESERVED FOR PRIVATE METHODS
support_version = ['\x05']                    # 目前仅支持 socks 版本 5.
support_method = ['\x00']                   # 
support_cmd = ['\x01']                          # 连接方式不支持 Bind('\x02') , UDP('\x03')
support_addr_type = ['\x01','\x03']    # 地址类型不支持 ( '\x04' )
support_protocol = ['HTTP']                # 目前只支持针对HTTP协议做优化处理,其它协议原封转发.

class Meet:
    def __init__(self,connection):
        self.connection = connection
        self.process_data(self.recv_data())
    def recv_data(self):
        return self.connection.recv(10)

    def process_data(self,data):
        print "握手. process_data: %s" %(repr(data))
        if data[:3] == "GET":
            self.connection.send(self.report_self())
            self.connection.close()
            return False
        elif len(data) == 3:
            if data[0] in support_version and data[1] in support_nmethod and data[2] in support_method:
                self.connection.send('\x05\x00')
                return True
        else:
            self.connection.send('\x05\xFF')
            self.connection.close()
            return False
    def report_self(self):
        "Return HTTP Content"
        http_response = "HTTP/1.1 200 OK\r\nServer: Python-Socks5/0.1 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: 89\r\nConnection: close\r\n\r\n<html><title>Python Proxy Server</title><h1>This Is One Socks Proxy Server.</h1></html>\r\n"
        return http_response


class Request:
    def __init__(self,connection,address):
        self.connection = connection
        print "获取请求数据..."
        return self.process_request(self.recv_request())
        
    def recv_request(self):
        header = list(self.connection.recv(5))
        print "获取请求数据. header. %s" % repr(header)
        #WARNING: 如果你开启了Socks 5 的远程DNS解析，那么请确保你所需要解析的 域名(DOMAIN)长度必须小于或等于127.
        #                      对于长度大于127位的长域名，请暂时关掉远程DNS解析。
        dst_addr = self.connection.recv(struct.unpack('b',header[4])[0])   #  -128 <= DST.ADDR Length <= 127
        dst_port = struct.unpack('!h',self.connection.recv(2) )[0]
        return {'header':header, 'dst_host':(dst_addr,dst_port) }

    def process_request(self,data):
        print "request .  Process data."
        dst_host = data['dst_host']
        ver = data['header'][0]
        cmd = data['header'][1]                     # CONNECT X'01'  BIND X'02'  UDP ASSOCIATE X'03'
        rsv = data['header'][2]
        self.addr_type = data['header'][3]  # IP V4 address: X'01'   DOMAINNAME: X'03'  IP V6 address: X'04'
        if cmd in support_cmd and ver in support_version and addr_type in support_addr_type:
            return self.replay(dst_host)
        else:
            if cmd not in support_cmd:
                # "\x07" 不支持的连接内型
                self.connection.send("\x05\x07\x00" + self.addr_type + struct.pack('b',len(dst_host[0])) + dst_host[0] + struct.pack('!h',dst_host[1])  )
            elif addr_type not in support_addr_type:
                # "\x08" 不支持的 地址类型
                self.connection.send("\x05\x08\x00" + self.addr_type + struct.pack('b',len(dst_host[0])) + dst_host[0] + struct.pack('!h',dst_host[1])  )
            else:
                # "\x09" 未知错误
                self.connection.send("\x05\x09\x00" + self.addr_type + struct.pack('b',len(dst_host[0])) + dst_host[0] + struct.pack('!h',dst_host[1])  )
    def replay(self,dst_host):
        try:
            print "request . replay."
            "Connection Remote Target Host."
            remote_connect = socket.socket()
            remote_connect.connect(dst_host)
            #NOTE: 远端连接为IP Number.
            remote_peer_name = remote_connect.getpeername()[0]  #  -128 <= remote_peer_name <= 127
            remote_port = remote_connect.getpeername()[1]
            "Replay Remote Target Host Connection Status."
            rep = struct.pack('bbbbb',5,0,0,1,len(remote_peer_name) )  # 5,0,0,1   : \x05\x00\x00\x01
            rep += remote_peer_name
            rep += struct.pack('!h',remote_port)
            self.connection.send(rep)
            return remote_connect
        except:
            "Remote Connection Faild."
            """
             X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
             """
            self.connection.send("\x05\x01\x00" + self.addr_type + struct.pack('b',len(dst_host[0])) + dst_host[0] + struct.pack('!h',dst_host[1])  )
            return False

class Transaction:
    "Forwarding Protocol Data"
    def __init__(self,l_connection,r_connection):
        self.l_connection = l_connection
        self.r_connection = r_connection
        print "交易信息..."
        request_data = self.recv_data(self.l_connection)
        remoet_data = self.forward_to_remote(self.r_connection,request_data)
        return self.forward_to_client(remoet_data)
    def recv_data(self,connection):
        # WARNING: 如果HTTP协议大小超过4096字节,并且在4096字节内无法读取到Content-Length字段
        #                       则该HTTP请求很有可能会失败！
        raw_request = connection.recv(4096)
        protocol = self.get_protocol(raw_request)
        if protocol == 'HTTP' and re.match("Content-Length: \d+",raw_request):
            http_content_length = int(re.compile("Content-Length: \d+").findall(raw_request)[0])
            buffer_total = http_content_length - len(raw_request.split('\r\n\r\n')[1])
            buffer_data = ""
            if buffer_total > 4096:
                while True:
                    buffer_total -= 4096
                    buffer_data += connection.recv(4096)
                    if buffer_total <= 0 :
                        break
            else:
                buffer_data += connection.recv(4096)
            request = raw_request + buffer_data
        return request
    
    def forward_to_remote(self,data):
        # Forward Client Request To Remote Target Server.
        if self.r_connection.send(data):
            return self.recv_data(self.r_connection)
        else:
            return False
    def forward_to_client(self,data):
        # Forward Server Response To Client Host.
        return self.l_connection.send(data)
    def get_protocol(self,data):
        if re.match("^\w+\s\S+\sHTTP\/\d.\d",data) and re.match("\r\n\r\n",data):
            "HTTP Protocol"
            return 'HTTP'
        

class Worker:
    "Process One Connection"
    def __init__(self,connection,address):
        self.connection = connection
        self.address = address
        try:
            meet = Meet(self.connection)
            if meet:
                remote_connect = Request(self.connection,self.address)
                if remote_connect:
                    if not Transaction(self.connection,remote_connect):
                        self.connection.close()
        except:
            try:
                self.connection.close()
            except:
                pass

def commander(ip,port):
    "Net Keeper ... "
    s = socket.socket()
    s.bind((ip,port))
    s.listen(1)
    
    while True:
        print("** 等待连接 ... ") 
        connection,address = s.accept()
        #connection.settimeout(10)
        print("** 与%s:%d建立连接 ... " %(address[0],address[1] ) )
        Worker(connection,address)
        s.close()
        break

if __name__ == '__main__':
    "代理服务器 地址及监听端口 "
    commander('127.0.0.1',1070)