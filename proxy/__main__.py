
from proxy import Proxy

if __name__ == '__main__':
    host  = "0.0.0.0"
    port  = 1070
    proxy = Proxy(host=host, port=port)
    proxy.run()