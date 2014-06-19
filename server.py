#!/usr/bin/env python
#-*- coding:utf-8 -*-
#Author:Luo Zijun
#Email:gnulinux@126.com

#PhotonVPS:23.228.235.130

#######################################################################################
##########################说明（DOC）###################################################
#File  :本地加密服务器                                                                                                                                                                                         #
#         主要作用是加密请求信息                                                                                                                                                                         #
#         使信息安全到达远程代理服务器（避免被防火墙（GFW）拦截）                                                                                               #
#Lib：binascii                                                                                                                                                                                                         #
#         该库为Python官方标准库                                                                                                                                                                        #
#         主要作用是对数据进行简单的处理（本程序未涉及加密，经本人亲自验证，可以绕过防火墙的关键词过滤系统）     #
#         使用方法：                                                                                                                                                                                                    #
#                binascii.b2a_hex(ASCII WORDS)              #将字符串转化为十六进制。                                                                                 #
#                binascii.a2b_hex(HEX)                                #将十六进制转化为字符串。                                                                                  #
#                更多：http://docs.python.org/2/library/binascii.html                                                                                                             #
#Lib：urllib2                                                                                                                                                                                                             #
#          该库为Python2.X版本的标准库，Python3.X下名字为urllib                                                                                                            #
#          使用方法：                                                                                                                                                                                                    #
#                参见：http://docs.python.org/2/library/urllib2.html                                                                                                                #
#Lib：socket                                                                                                                                                                                                             #
#          该库为Python2.X版本的标准库                                                                                                                                                               #
#          使用方法：                                                                                                                                                                                                    #
#                参见：http://docs.python.org/2/library/socket.html                                                                                                                #
#######################################################################################
#######################################################################################

from __future__ import division
import socket
import urllib2,urllib
import binascii
import zlib

#对整除法和真除法进行分工（//整除，/表示真除）

browser_request = """
'GET http://baidu.com/favicon.ico HTTP/1.1\r\nHost: baidu.com\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0\r\nAccept: image/png,image/*;q=0.8,*/*;q=0.5\r\nAccept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nCookie: BAIDUID=175CE6807566D9E8D27DBFA3C04467FA:FG=1; BDUSS=E43TUp-SlFUZ3YtLW1ZeWc1bm41RH5wZn5GMllkbmxvNG16RmpaSWFPdm0tODFSQVFBQUFBJCQAAAAAAAAAAAEAAACrj0cJYXN6aWp1bgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOZuplHmbqZRd; SSUDBTSP=1369861862; SSUDB=E43TUp-SlFUZ3YtLW1ZeWc1bm41RH5wZn5GMllkbmxvNG16RmpaSWFPdm0tODFSQVFBQUFBJCQAAAAAAAAAAAEAAACrj0cJYXN6aWp1bgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOZuplHmbqZRd; BAIDU_WISE_UID=bd_1370930205_669; MCITY=-218%3A; H_PS_PSSID=3407_3444_1430_2981\r\nConnection: keep-alive\r\n\r\n'
"""

squid_res ="""
'HTTP/1.0 200 OK\r\nDate: Sat, 12 Oct 2013 13:40:46 GMT\r\nServer: Apache\r\nLast-Modified: Mon, 24 Jan 2011 11:52:00 GMT\r\nETag: "13e-4d3d67e0"\r\nAccept-Ranges: bytes\r\nContent-Length: 318\r\nContent-Type: text/plain\r\nAge: 56103\r\nX-Cache: HIT from localhost\r\nX-Cache-Lookup: HIT from localhost:3128\r\nVia: 1.1 localhost:3128 (squid/2.7.STABLE9)\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n\x00\x00\x01\x00\x01\x00\x10\x10\x10\x00\x01\x00\x04\x00(\x01\x00\x00\x16\x00\x00\x00(\x00\x00\x00\x10\x00\x00\x00 \x00\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x80\x00\x00\x00\x80\x80\x00\x80\x00\x00\x00\x80\x00\x80\x00\x80\x80\x00\x00\x80\x80\x80\x00\xc0\xc0\xc0\x00\x00\x00\xff\x00\x00\xff\x00\x00\x00\xff\xff\x00\xff\x00\x00\x00\xff\x00\xff\x00\xff\xff\x00\x00\xff\xff\xff\x00\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcf\xff\xff\xff\xff\xff\xff\xfc\xcf\xf8\xcc\xc7|\xcc\x8f\xfc\xcf\xfc\xcc\xcc\xcc\xcc\xcf\xfc\xcf\xfc\xcc\xcc\xcc\xcc\xcf\xfc\xcf\xf8\xcc\xcc\xcc\xcc\x8f\xfc\xcf\xff\x8c\xcc\xcc\xc8\xff\xfc\xcf\x8c\x88\xcc\xcc\x88\xc8\xfc\xcf\xcc\xcf\x8c\xc8\xfc\xcc\xfc\xcf\xcc\xcf\xff\xff\xf8\xc8\xfc\xcf\x8c\x88\xc8\xf8\xc8\xff\xfc\xcf\xff\xfc\xcc\xfc\xcc\xff\xfc\xcf\xff\xfc\xcc\xfc\xcc\xff\xfc\xcf\xff\xf8\xc8\xff\x8f\xff\xfc\xcf\xff\xff\xff\xff\xff\xff\xfc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
"""



#网络套接字超时时间（具有全局性），单位：秒
timeout = 20
#socket.setdefaulttimeout(timeout)
#远程代理服务器地址和端口（远程服务器）
vps_ip = "23.228.235.130"
vps_port = 3333
#本服务器的地址和端口（本地服务器）
ip = "127.0.0.1"
port = 4444
#服务器最多连接请求数量
listen = 40
#管理员信息
admin_email = "gnulinux@126.com"

def con_vps(request):
    #和VPS代理服务器建立连接
    ip = vps_ip
    port = vps_port
    c = socket.socket()
    c.settimeout(10)
    try:
        c.connect((ip,port))

    except:
        print "错误：连接远程代理服务器失败！"
    try:
        print request
        c.send(request)
        print "向远程代理服务器发送数据完毕"
    except:
        return "错误：向远程代理发送数据失败！"
    try:
        ###从VPS接收数据
        data = ""
        a = True
        while a:
            buff = c.recv(1024)
            if not buff:
                print "DEBUG：从VPS发送过来的数据已经全部接收！"
                a = False
            if buff:
                data = str(data) + str(buff)
                a = True
                #print buf
        #print data
        return data
    except:
        print "DEBUG：从VPS接收数据失败！"
        return "接收数据失败！--VPS"



def recv_data(cs):
    #获取套接字数据包
    #buff = s.recv(2048)
    cs.settimeout(20)
    data = ""
    #run = True
    buff = cs.recv(2048)
    return buff
    """
    while True:
        buff = cs.recv(1024)
        if buff:
            data = str(data) + str(buff)
        if not buff:
            #run = False
            break
    if data:
        return data
    if not data:

        print  "错误，从浏览器数据接收失败！"
        return False
"""
def urllib_get(request):
    #使用Python Urllib2标准库对基于超文本协议的地址进行连接
    request_array = request.split("\r\n")
    #请求地址（Request-Line）
    url =  request_array[0].split(" ")[1]
    #删除Request-line不规则数据
    del request_array[0]
    #组装字典数据
    request_dict = {}
    for x in request_array:
        try:
            r_dict = x.split(": ")
            request_dict[r_dict[0]] = r_dict[1]
        except:
            #此处出错一般是此处的头信息为空。忽略
            print "提取请求头信息失败！"
    headers = request_dict
    try:
        req = urllib2.Request(url, headers)
        res = urllib2.urlopen(req)
        #获取服务器返回的headers
        response_headers = dict(res.headers)
        res_header = "HTTP/1.0 " + str(res.code) + " " + str(res.msg) +"\r\n"
        res_headers_keys = response_headers.keys()
        lines = ""
        for x in res_headers_keys:
            lines = lines + x + ": " + response_headers[x] + "\r\n"
        lines = lines + "\r\n"
        res_headers = res_header + lines
        res_data = res_headers + res.read()
        return res_data

    except:
        #urllib2 错误！
        return "错误：urllib2与目标地址的连接出现错误！"


def work(s,cs,address):
    #主工作函数
    access_ip = str(address[0]) + ":" + str(address[1])
    print "         @@开始处理来自 %s 的连接……" % str(access_ip)
    try:
        #调用CONN类中的Recv_data 函数进行接收数据
        request_data = recv_data(cs)
        #从请求数据当中提取万维网地址信息
        url =  (request_data.split("\r\n"))[0].split(" ")[1]
        #print repr(request_data)
    except:
        print "请求VPS不正常。。。"
        return
    #*****重点*****#
    #十进制原始数据转换十六进制（必要时可以在此把马上需要发送给远程代理的数据进行处理，避免防火墙（GFW）的审查拦截！）
    request = binascii.b2a_hex(request_data)
    print "请求地址为：%s" %url
    print "向远程代理服务器发送加密请求：\n%s" % str(request)
    res_data = con_vps(request)  #发送经过处理的数据（最好是加密）
    print ">"*150
    #尝试把远程服务器返回的十六进制数据转换成十进制（需要判断字符串是否为十六进制数据）
    if res_data:
        try:
            res = binascii.a2b_hex(res_data)
            print "<"*150
            print "远程代理服务器返回加密的结果：\n%s" %str(res_data)
            print "DEBUG：从VPS返回的数据已经解密！\n 长度：%s\n" % str(len(res))
            #把已经解密的数据返回给用户
            try:
                cs.send(res)
                print "         @@数据已经发送给用户"
            except:
                print "         ***错误：与用户的连接已经中断，数据发送失败！"

        except:
           #含有非十六进制字符，很有可能返回的是出错提示！
            print "         *||||* %s" %(str(res_data))
            #返回用户错误信息。
            msg = "<h1>请求错误</h1>\n<p>错误原始信息：%s </p>\n<br><p><b>请联系管理员：</b>%s</p><br>\n" %(str(res_data),admin_email)
            try:
                cs.send(msg)
                print " DEBUG：        @错误信息已经发送给用户"
                #关闭套接字连接
                #cs.close()
            except:
                print "         ***错误：与用户的连接已经中断，数据发送失败！"
    else:
        print "DEBUG：数据返回错误！"
    cs.close()
    print "         @@与用户的连接已断开。"

def send_to_server(raw_data):
    #发送数据到代理服务器
    #加密（这里我只是简单的转换进制，经观察可以躲避防火墙的拦截）

    #创建到服务器之间的连接
    try:
        c = socket.socket()
        c.connect((vps_ip,vps_port))
    except:
        print "：：与VPS服务器的连接建立失败！"
        c.close()
        return False

    hex_data = binascii.b2a_hex(raw_data)  #把十进制转换为十六进制数据
    #压缩数据（使用zlib库，可以使用zip库，压缩效率暂无法比较）
    compress_data = zlib.compress(hex_data)
    #发送数据，遵循协议，首先发送包头（含有正文长度）
    if (float(len(compress_data))/1000) > (len(compress_data)//1000):
        pack_num = len(compress_data)//1000 +1
    else:pack_num = (len(compress_data))//1000
    try:
        c.send(str(pack_num))   #向服务器发送数据包个数（每个1000字节）
    except:
        print "：：向VPS服务器发送加密数据失败！"
        c.close()
        return False
    try:
        #接收代理服务器返回数据（ ready access）
        is_ready = c.recv(1000) #判断服务器是否就绪，并准备接收数据
        if is_ready == "00":
            print "**服务器未就绪！返回数据：%s" %(is_ready)
            c.close()
            return False
    except:
        print "：：从服务器接收 就绪 数据失败，服务器未就绪……"
        c.close()
        return False
    #开始向服务器发送压缩过的加密数据
    try:
        num = -1
        while num < (pack_num-1):
            num += 1
            try:
                c.send(compress_data[num:1000])
                print "：：成功向服务器发送数据包 %s/%s" %(str(num+1),str(pack_num))
            except:
                print "：：向服务器发送数据包 %s/%s 失败！\s：：开始重试" %(str(num+1),str(pack_num))

                return num-1
                #break
    except:
        print "：：发送数据库循环出现故障！"
        c.close()
        return False
    #验证服务器是否正确收到所有数据包
    try:
        is_copy = c.recv(1024)
        if is_copy == "00":
            print "**服务器未完全收到所有的数据包，返回数据代码：%s" %(is_copy)
            c.close()
            return False
    except:
        print "：：验证服务器数据包失败，服务器未完全收到所有数据包！"
        c.close()
        return False
    #获取服务器响应数据（服务器执行了请求数据返回的结果）
    try:
        res_pack_nums = c.recv(1024)
    except:
        print "：：获取远程服务器 返回结果数据 头信息包错误！"
        c.close()
        return False
    try:
        compress_res_data = ""
        num = -1
        while num < (res_pack_num-1):
            num += 1
            try:
                res = c.recv(1000)
                compress_res_data += res
                print "：：成功接收到远程服务器发送数据包 %s/%s" %(str(num+1),str(res_pack_num))
            except:
                print "：：接收远程服务器发送的数据包 %s/%s 失败！" %(str(num+1),str(res_pack_num))
                #return num = num-1
                compress_res_data = ""
                break
        if compress_res_data == "":
            print "：：接收远程服务器数据包失败！"
            c.close()
            return False
        else:
            #开始解压缩数据
            raw_data = zlib.decompress(compress_res_data)
            return raw_data
    except:
        print "：：接收远程服务器数据包失败！"
        try:
            c.close()
        except:
            pass
        return False


if __name__ == "__main__":
    #运行主函数
    s = socket.socket()
    #本地服务端端口和地址。
    #port = raw_input("请输入本地代理服务器监听端口：")
    port = raw_input("Port:")
    s.bind((ip,int(port)))
    s.listen(listen)
    print "@@进程开始在端口 %s 处监听……"  % (str(port))
    #进入工作循环
    try:
        while True:
            print "-"*130
            print "@@等待用户连接 . . . "
            cs,address = s.accept()
            cs.settimeout(2)
            print "     @@正在和 %s:%s 建立连接……" %( str(address[0]),str(address[1])   )
            data = ""
            while True:
                try:
                    buff = cs.recv(6048)  #接收不定长数据包（浏览器发来的数据长度充满不确定性）
                    data += buff
                except:
                    break

            #if not data:
            #    return
            print "DEBUG : if data \n%s" % str(data)
            if data != "" or data != False:
                try:
                    url =  (data.split("\r\n"))[0].split(" ")[1]
                    print ">"*150
                    print "：：请求地址：%s" %url
                    status = send_to_server(data)  #调用向服务器发送数据包函数
                    if status != False:
                        try:
                            cs.send(status)
                        except:
                            print "：：返回浏览器数据失败！"
                    if status == False:
                        #向服务器发送数据失败！
                        print "：：向服务器发送数据失败！"
                except:
                    print "DEBUG: 2"
            if not data:
                break
    except KeyboardInterrupt:
        print "you have CTRL+C,Now quit!"
        s.close()
