#!/usr/bin/env python
#-*- coding:utf-8 -*-

class DummySocket:
    def __init__(self, buff="", connection=None):
        self.connection = connection
        self.buff       = buff
    def recv(self, num):
        if len(self.buff) > 0:
            if num > len(self.buff):
                return self.buff + self.connection.recv(num-len(self.buff))
            elif num == len(self.buff):
                return self.buff
            elif num < len(self.buff):
                return self.buff[0:num]
            else:
                pass
        else:
            return self.connection.recv(num)
    def read(self, num):
        return self.recv(num)
    def getBuff(self):
        pass