#!/usr/bin/env python
#-*- coding:utf-8 -*-

from   urlparse    import urlparse
import methods     as Methods

from   proxy.utils import DummySocket


CRLF = "\r\n"
# 413 Entity Too Large
HTTP_HEADER_LENGTH_LIMIT = 20480



class Request:
    host     = ""
    port     = 80     # HTTP: 80, HTTPS: 443
    scheme   = "http" # HTTP, HTTPS, if methods is `CONNECT`, protocol will be TCP.

    method   = ""     # HTTP Methods
    path     = ""     # Path Name
    query    = ""     # Query Sting
    fragment = ""     # Hash Node
    
    header   = {}     # HTTP Header
    body     = ""     # HTTP Body
    version  = "1.1"  # HTTP Version

    def __init__(self, buff="", connection=None):
        self.connection = connection
        self.buff       = buff

    def _read_header(self):
        while True:
            _tmp = conn.recv(4096)
            if not _tmp: break
            self.buff += _tmp
            if CRLF*2 in self.buff:
                break
            elif len(self.buff) > HTTP_HEADER_LENGTH_LIMIT:
                raise IOError('Entity Too Large')

    def _read_body(self):
        if "content-length" in self.header:
            body_size = int(self.header['content-length'])
            self.body += self.connection.recv(body_size-len(self.body))
        elif "transfer-encoding" in self.header and self.header['transfer-encoding'] == 'chunked':
            self.body = self._read_chunked()
        else:
            # Body Content is empty.
            pass

    def _read_chunked(self):
        fd   = DummySocket(buff=self.body, connection=self.connection)
        body = ""
        while True:
            tmp = fd.recv(1)
            if not tmp: break
            if CRLF in tmp:
                size = int(tmp[:-2], 16)
                body += fd.recv(size)
                fd.recv(len(CRLF))
                if size == 0: break
        return body

    def read(self):
        self._read_header()
        self._parse_first_line()
        self._parse_header()
        self._read_body()

    def _parse_first_line(self):
        line = self.buff.split(CRLF)[0]
        method, uri, protocol = line.split(" ")
        
        self.version = protocol.split("/")[1]

        self.method  = method
        # ParseResult(scheme='scheme', netloc='index', path='', params='', query='', fragment='')
        # scheme://www.domain.com/pathname?query=string#fragment

        if "://" not in uri:
            if not uri.startswith("/") and  "." not in uri:
                uri = "/" + uri
            uri = "scheme://" + uri
        
        result  = urlparse(uri)

        if ":" in result.netloc:
            self.host, self.port = result.netloc.split(":")
            try:
                self.port = int(self.port)
            except:
                pass
        else:
            if result.scheme == 'http':
                self.port    = 80
            elif result.scheme == 'https':
                self.port    = 443
            else:
                pass
            self.host = result.netloc

        # Path Name
        location     = result.path
        if result.query:
            location = "?".join((location, result.query))
        if result.fragment:
            location = "#".join((location, result.fragment))

        if result.scheme == "scheme":
            if self.method == Methods.CONNECT:
                self.scheme = "tcp"
            else:
                self.scheme = "http"
        else:
            self.scheme     = result.scheme


    def _parse_header(self):
        if CRLF*2 not in self.buff:
            raise IOError('Entity Too Large')
        _tmp = self.buff.split(CRLF*2)
        header = _tmp[0]
        body   = (CRLF*2).join(_tmp[1:])
        # del _tmp
        for line in header.split(CRLF):
            key, value = line.split(": ")
            self.header[key.lower()] = value
        self.body      = body



