#!/usr/bin/env python
#-*- coding:utf-8 -*-
#Author:Luo Zijun
#Email:gnulinux@126.com

#PhotonVPS:23.228.235.130

#######################################################################################
##########################说明（DOC）###################################################
#File  :本地代理服务器                                                                 #
#         主要作用是加密请求信息                                                        #
#         使信息安全到达远程代理服务器（避免被防火墙（GFW）拦截）                          #
#Lib：binascii                                                                                                                                                                                                         #
#         该库为Python官方标准库                                                            #
#         主要作用是对数据进行简单的处理（本程序未涉及加密，经本人亲自验证，可以绕过防火墙的关键词过滤系统）#
#         使用方法：                                                                  #
#                binascii.b2a_hex(ASCII WORDS)              #将字符串转化为十六进制。  #
#                binascii.a2b_hex(HEX)                                #将十六进制转化为字符串。                                                                                  #
#                更多：http://docs.python.org/2/library/binascii.html                                                                                                             #
#Lib：urllib2                                                                                                                                                                                                             #
#          该库为Python2.X版本的标准库，Python3.X下名字为urllib                           #
#          使用方法：                                                                             #
#                参见：http://docs.python.org/2/library/urllib2.html                                                                                                                #
#Lib：socket                                                                                                                                                                                                             #
#          该库为Python2.X版本的标准库                                                         #
#          使用方法：                                                                               #
#                参见：http://docs.python.org/2/library/socket.html                                                                                                                #
#######################################################################################
#######################################################################################
from __future__ import division
#对整除法和真除法进行分工（//整除，/表示真除）
import socket
import urllib2,urllib
import binascii
import zlib


browser_request = """
'GET http://baidu.com/favicon.ico HTTP/1.1\r\nHost: baidu.com\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0\r\nAccept: image/png,image/*;q=0.8,*/*;q=0.5\r\nAccept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nCookie: BAIDUID=175CE6807566D9E8D27DBFA3C04467FA:FG=1; BDUSS=E43TUp-SlFUZ3YtLW1ZeWc1bm41RH5wZn5GMllkbmxvNG16RmpaSWFPdm0tODFSQVFBQUFBJCQAAAAAAAAAAAEAAACrj0cJYXN6aWp1bgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOZuplHmbqZRd; SSUDBTSP=1369861862; SSUDB=E43TUp-SlFUZ3YtLW1ZeWc1bm41RH5wZn5GMllkbmxvNG16RmpaSWFPdm0tODFSQVFBQUFBJCQAAAAAAAAAAAEAAACrj0cJYXN6aWp1bgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOZuplHmbqZRd; BAIDU_WISE_UID=bd_1370930205_669; MCITY=-218%3A; H_PS_PSSID=3407_3444_1430_2981\r\nConnection: keep-alive\r\n\r\n'
"""

squid_res ="""
'HTTP/1.0 200 OK\r\nDate: Sat, 12 Oct 2013 13:40:46 GMT\r\nServer: Apache\r\nLast-Modified: Mon, 24 Jan 2011 11:52:00 GMT\r\nETag: "13e-4d3d67e0"\r\nAccept-Ranges: bytes\r\nContent-Length: 318\r\nContent-Type: text/plain\r\nAge: 56103\r\nX-Cache: HIT from localhost\r\nX-Cache-Lookup: HIT from localhost:3128\r\nVia: 1.1 localhost:3128 (squid/2.7.STABLE9)\r\nConnection: keep-alive\r\nProxy-Connection: keep-alive\r\n\r\n\x00\x00\x01\x00\x01\x00\x10\x10\x10\x00\x01\x00\x04\x00(\x01\x00\x00\x16\x00\x00\x00(\x00\x00\x00\x10\x00\x00\x00 \x00\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x80\x00\x00\x00\x80\x80\x00\x80\x00\x00\x00\x80\x00\x80\x00\x80\x80\x00\x00\x80\x80\x80\x00\xc0\xc0\xc0\x00\x00\x00\xff\x00\x00\xff\x00\x00\x00\xff\xff\x00\xff\x00\x00\x00\xff\x00\xff\x00\xff\xff\x00\x00\xff\xff\xff\x00\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcf\xff\xff\xff\xff\xff\xff\xfc\xcf\xf8\xcc\xc7|\xcc\x8f\xfc\xcf\xfc\xcc\xcc\xcc\xcc\xcf\xfc\xcf\xfc\xcc\xcc\xcc\xcc\xcf\xfc\xcf\xf8\xcc\xcc\xcc\xcc\x8f\xfc\xcf\xff\x8c\xcc\xcc\xc8\xff\xfc\xcf\x8c\x88\xcc\xcc\x88\xc8\xfc\xcf\xcc\xcf\x8c\xc8\xfc\xcc\xfc\xcf\xcc\xcf\xff\xff\xf8\xc8\xfc\xcf\x8c\x88\xc8\xf8\xc8\xff\xfc\xcf\xff\xfc\xcc\xfc\xcc\xff\xfc\xcf\xff\xfc\xcc\xfc\xcc\xff\xfc\xcf\xff\xf8\xc8\xff\x8f\xff\xfc\xcf\xff\xff\xff\xff\xff\xff\xfc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
"""





#网络套接字超时时间（具有全局性），单位：秒
timeout = 10
#socket.setdefaulttimeout(timeout)
#代理服务器地址和端口
ip = "23.228.235.130"
port = 3333
#最多连接请求数
listen = 40
#管理员信息
admin_email = "gnulinux@126.com"



def con_vps(self,request):
    #和VPS代理服务器建立连接
    ip = vps_ip
    port = vps_port
    c=socket.socket()
    try:
        c.connect((ip,port))
    except:
        return "错误：连接服务器失败！"
    try:
        c.send(request)
    except:
        return "错误：数据发送失败！"
    data = recv_data(c)
    c.close()
    return data

def recv_data(cs):
    #获取套接字数据包
    data = ""
    run = True
    while run:
        #try:
        buff = cs.recv(1024)
        if not buff:
            run = False
        elif buff:

            data = str(data) + str(buff)
    if data:
        return data
    if not data:
        return  "错误：数据包为空！"


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
            pass
    headers = request_dict
    try:
        #print "DEBUG Function->urllib_get ：\n%s\n%s" %(str(url),str(headers))
        req = urllib2.Request(url,None,headers)
        #print req
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
        print  "错误：urllib2与目标地址的连接出现错误！"
        return False







def work(s,cs,address):
    #工作主函数
    access_ip = str(address[0]) + ":" + str(address[1])
    print "         @@开始处理来自 %s 的连接……" % str(access_ip)
    #调用CONN类中的Recv_data 函数进行接收数据
    request_data = recv_data(cs)
    #s.close()
    print "尝试解密：\n%s" %(str(request_data))
    #尝试把接收到的十六进制数据转换成十进制（需要判断字符串是否为十六进制数据）
    if request_data:
        try:
            request = binascii.a2b_hex(request_data)
            print "DEBUG：解密完成！"
            print ">"*150
            #print "获取解密数据：\n%s" %(str(request))
            request_array = request.split("\r\n")
            #请求地址（Request-Line）
            url =  request_array[0].split(" ")[1]
            print "调用urllib2标准库执行超文本协议请求：\n%s" % str(url)
            res_data = urllib_get(request)
            print "<"*150
            print "urllib2标准库返回结果长度：\n%s" %str(len(res_data))
            #加密已获取的数据，准备发送给客户端
            if res_data:
                res = binascii.b2a_hex(res_data)
            else:
                print "urllib获取回来的数据为空！"
                res = binascii.b2a_hex("错误：urllib获取回来的数据为空！")
            #把已经解密的数据返回给用户
            try:
                cs.send(res)
                #cs.close()
                print "         @@数据已经发送给用户"
            except:
                print "         ***错误：与用户的连接已经中断，数据发送失败！"
        except:
            #含有非十六进制字符，很有可能返回的是出错提示！
            print "         *||||* %s" %(str(request_data))
            #返回用户错误信息。
            msg = "<h1>请求错误</h1>\n请求地址：<li><a href=\"%s\">%s</a></i><p>错误原始信息：%s </p>\n<br><p><b>请联系管理员：</b>%s</p><br>\n" %(url,url,str(request_data),admin_email)
            try:
                cs.send(msg)
                print "DEBUG ：返回错误信息返回结束!"
                #关闭套接字连接
                #cs.close()
            except:
                print "         ***错误：与用户的连接已经中断，数据发送失败！"

    else:
        print "DEBUG：数据返回错误！！！"
    cs.close()
    print "         @@与用户的连接已断开。"


def recv_one(cs):
    #获取只有一个封包的数据
    try:
        a = cs.recv(1000)
        return a
    except:
        print "：连接超时"
        return False

def recv_many(cs,pack_num):
    if pack_num <1 or pack_num ==1:
        print "：数据包不能少于一个！"
        #return False
        a = recv_one(cs)
        return a
    else:
        data = ""
        num = -1
        get_num = 0
        while num <(pack_num-1):
            try:
                buff = cs.recv(1000)
                get_num += 1
                data += buff
            except:
                if get_num == pcak_num:
                    print "：数据包全部接收完毕！"
                    break
                else:
                    print ":数据包不完整，丢弃！  get_num:%s" %str(get_num)
                    data = False
                    break
        if data != False:
            return data
        elif data == False:
            return False

def get_packs_num(cs,pack_num):
    #获取第一次握手发来的数据包数量
    if pack_num:
        compress_data = ""
        num = -1
        while num <(pack_num-1):
            num += 1
            if pack_num == 1:
                try:
                    compress_data = cs.recv(1000)
                    break
                except:
                    compress_data = False
                    cs.close()

                    break
            try:
                res = cs.recv(1000)
                compress_data += res
                print "：：成功接收到远程服务器发送数据包 %s/%s" %(str(num+1),str(pack_num))
            except:
                #print "：：接收远程服务器发送的数据包 %s/%s 失败！" %(str(num+1),str(pack_num))
                compress_data = False
                break

        if compress_data == False:
            print "接收加密服务器的加密数据包失败！"
            #告诉客户端数据收取失败，通知结束连接
            try:
                cs.send("00")
                cs.close()
            except:
                cs.close()
                pass
            return False
        else:
            #开始解压数据
            #告诉客户端数据收取成功，保持连接
            try:
                cs.send("11")
            except:
                pass
            hex_data = zlib.decompress(compress_data)
            #转换进制！ 把十六进制转换成十进制
            raw_data = binascii.a2b_hex(hex_data)
            return raw_data
    else:
        return False
    #except:
    #    print "“”接收加密服务器的加密数据包失败！"
        #告诉客户端数据收取失败，通知结束连接
    #    try:
            #cs.send("00")
        #except:

         #   pass
        #return False
def send_one(cs,data):
    #发送一个数据包
    #注意数据包应该都是压缩过和加密过的。
    if len(data)< 1000 or len(data) == 1000:
        try:
            cs.send(data)
            return True
        except:
            print "：数据包发送失败！"
            return False
    else:
        print "你发送的数据包大于1000，被拒绝！"
        return False

def send_many(cs,data):
    #发送超过1000大小的数据包
    if len(data) >1000:
        data_len_f = float(len(data))
        data_len_i = int(len(data))
        if data_len_f/1000 > data_len_i//1000:
            pack_num = len(data)//1000 +1
        else:pack_num = (len(compress_data))//1000
        try:
            cs.send(str(pack_num))
        except:
            print "向加密服务器发送数据包数量出错！"
            return False
        try:
            num = -1
            while num < (pack_num-1):
                num += 1
                try:
                    cs.send(data[num:1000])
                    print "：：成功向加密服务器发送数据包 %s/%s" %(str(num+1),str(pack_num))
                except:
                    print "：：向加密服务器发送数据包 %s/%s 失败！" %(str(num+1),str(pack_num))
                    break
                    #return num-1
            return True
        except:
            print "：：发送数据封包循环出现故障！"
            return False
    else:
        print "：你发送的数据包过小,改用单个发送"
        return send_one(cs,data)


def back_compress_data(cs,compress_data):
    #返回加密服务器经过压缩和加密的数据
    if (float(len(compress_data))/1000) > (len(compress_data)//1000):
        pack_num = len(compress_data)//1000 +1
    else:pack_num = (len(compress_data))//1000
    try:
        cs.send(str(pack_num))   #向服务器发送数据包个数（每个1000字节）
    except:
        print "：：加密服务器发送加密数据封包头信息失败！"
        return False
    #向加密服务器发送封包流
    try:
        num = -1
        while num < (pack_num-1):
            num += 1
            try:
                cs.send(compress_data[num:1000])
                print "：：成功向加密服务器发送数据包 %s/%s" %(str(num+1),str(pack_num))
            except:
                print "：：向加密服务器发送数据包 %s/%s 失败！\s：：开始重试" %(str(num+1),str(pack_num))
                return num-1
                #break
    except:
        print "：：发送数据封包循环出现故障！"
        return False




if __name__ == "__main__":
    #运行主函数
    s = socket.socket()
    #本地服务端端口和地址。
    #port = raw_input("请输入本地代理服务器监听端口：")
    s.bind((ip,port))
    s.listen(listen)
    print "@@进程开始在端口 %s 处监听……"  % (str(port))
    #进入工作循环
    try:
        while True:
            print "-"*150
            print "@@等待用户连接 . . . "
            cs,address = s.accept()
            cs.settimeout(10)
            print "     @@正在和 %s:%s 建立连接……" %( str(address[0]),str(address[1])   )
            #print "DEBUG....."
            while True:
                #print "DEBUG :SERVER 1"
                try:
                    #pack_num = int(cs.recv(1000))  #接收头信息，返回整数数据
                    pack_num = int(recv_one(cs))
                    print "：：数据包数量：%s" %str(pack_num)
                    break
                except:
                    print "pack_num == false!!!"
                    pack_num = False
                    break
            if pack_num == False:
                print "获取请求头信息数据失败"
                cs.close()

            else:
                #raw_data = get_packs_num(cs,pack_num)  #此函数负责和加密服务器进行交互
                if pack_num == 1:
                    raw_data = recv_one(cs)
                elif pack_num >1:
                    raw_data = recv_many(cs,pack_num)
                elif pack_num == 0:
                    raw_data = False
                if raw_data == False:
                    #接收头信息失败
                    print "raw_data:False"
                else:
                    #十六 -》10
                    hex_resdata = zlib.decompress(raw_data)
                    raw_resdata = binascii.a2b_hex(hex_resdata)
                    #发送给urllib2类分析并执行请求！
                    raw_res = urllib_get(raw_resdata)
                    if raw_res != False:
                        #对数据进行加密,转换进制
                        hex_res = binascii.b2a_hex(raw_res)
                        #对数据进行压缩处理zlib
                        compress_res = zlib.compress(hex_res)
                        #向 加密服务器返回 加密并且压缩过的数据！
                        #send_staus = back_compress_data(cs,compress_res)  #调用函数
                        status = send_many(cs,compress_res)
                        if status:
                            print "：数据发送成功！"
                        else:
                            print "：数据发送失败！"
                        #TODO:
                        #1.对客户端收数据同样进行验证！
                        #2.采用多线程模式，以增加网络IO响应速度
    except KeyboardInterrupt:
        print "you have CTRL+C,Now quit!"
        s.close()
