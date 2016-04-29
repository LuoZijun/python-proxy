#!/usr/bin/env python
#-*- coding:utf-8 -*-

import os, sys, time
import socket, struct, select
import thread, logging

import protocols


reload(sys)
sys.setdefaultencoding('utf8')

logging.basicConfig(
    # filename ='proxy.log',
    format  = '%(asctime)s %(message)s',
    datefmt = '%Y-%m-%d %H:%M:%S',
    level   = logging.DEBUG
)

class Session:
    def __init__(self, session=None, host="", port=0 ):
        self.session    = session
        self.host       = host
        self.port       = port
    def begin(self):
        try:
            self.start()
        except socket.timeout:
            logging.info('[Session] Session %s:%d timeout.' % (self.host, self.port) )
        except (KeyboardInterrupt, SystemExit):
            self.close()
            raise KeyboardInterrupt
        finally:
            try:
                self.close()
            except Exception as e:
                logging.debug(e)

    def start(self):
        
        buff, protocol = protocols.guess_protocol(self.session)

        if protocol == "socks":
            logging.info('[Session] protocol is Socks')
            handle = protocols.socks.Socks(buff=buff, session=self.session)
            handle.handle()
            self.close()

        elif protocol == "http":
            logging.info('[Session] protocol is Http')
            # handle = protocols.http.Http(buff=buff, session=self.session)
            self.close()

        elif protocol == "ftp":
            # handle = protocols.ftp.Ftp(buff=buff, session=self.session)
            logging.info('[Session] unsupport protocol ')
            self.close()
        elif protocol == "ssl":
            # handle = protocols.ssl.Ssl(buff=buff, session=self.session)
            logging.info('[Session] unsupport protocol ')
            self.close()
        else:
            logging.info('[Session] unknow protocol ')
            self.close()

    def close(self):
        logging.info('[Session] Session %s:%d close.' % (self.host, self.port) )
        return self.session.close()


class Proxy:
    def __init__(self, host="0.0.0.0", port=1070):
        self.host  = host
        self.port  = port

    def run(self):
        try:
            self.server = socket.socket()
            self.server.bind((self.host, self.port))
            self.server.listen(100)
        except Exception as e:
            logging.debug("[Server] Can not make proxy server on %s:%d " %(self.host, self.port) )
            logging.debug(e)
            return self.shutdown()

        logging.info("[Server] Proxy Server running on %s:%d ..." %(self.host, self.port))

        # run forever
        try:
            self.loop()
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception as e:
            logging.info('[Server] Unknow error ...')
            logging.info(e)
        finally:
            self.shutdown()

    def shutdown(self):
        logging.info('[Server] Shutdown Proxy server ...')
        return self.server.close()

    def loop(self):
        while True:
            connection, address = self.server.accept()
            session             = Session(session=connection, host=address[0], port=address[1])
            try:
                thread.start_new_thread(session.start, () )
            except Exception as e:
                logging.debug("[Server] 会话异常...")
                logging.info(e)
                session.close()


if __name__ == '__main__':
    host  = "0.0.0.0"
    port  = 1070
    proxy = Proxy(host=host, port=port)
    proxy.run()

