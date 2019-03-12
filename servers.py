SERVER_PORTS = {'21': 'FTP Server',\
                '23': 'Telnet Server',\
                '25': 'SMTP Server',\
                '53': 'DNS Server',\
                '80': 'HTTP Server',\
                '110': 'POP3 Server',\
                '123': 'NTP Server',\
                '443': 'HTTPS Server',\
                '465': 'SMTP Server',\
                '547': 'DHCPv6 Server',\
                '587': 'SMTP Server'\
                }


def coroutine(func):
    def start(*args,**kwargs):
        cr = func(*args,**kwargs)
        next(cr)
        return cr
    return start


class CaptureServers(object):
    def __init__(self, cap=None, defined_only=False):
        self._dict = {}
        self.defined_only = defined_only

        if cap is not None:
            for packet in cap:
                self.find(packet)
            self.pretty_print(defined_only)
        else:
            self.capture = self._capture()


    def __next__(self):
        if hasattr(self, 'capture'):
            next(self.capture)


    @coroutine
    def _capture(self):
        try:
            while True:
                packet = (yield)
                self.find(packet)
        except GeneratorExit:
            self.pretty_print()


    def send(self, packet):
        if hasattr(self, 'capture'):
            self.capture.send(packet)


    def close(self):
        if hasattr(self, 'capture'):
            self.capture.close()


    def if_add_server(self, ip, port):
        server_name = self.server_name(port)
        if server_name:
            self.add(ip, server_name)


    @staticmethod
    def server_name(port):
        if port in SERVER_PORTS.keys():
            return SERVER_PORTS[port]
        elif 0 < int(port) < 1024:
            return "port {port} (Not Defined)".format(port=port)
        return None


    def add(self, ip, server_name):
        if not ip in self._dict.keys():
            self._dict[ip] = []
        self._dict[ip] = list(set(self._dict[ip]).union([server_name]))


    def find(self, packet):
        if 'ip' in dir(packet):
            if 'tcp' in dir(packet):
                self.if_add_server(packet.ip.src, packet.tcp.srcport)
                self.if_add_server(packet.ip.dst, packet.tcp.dstport)
            if 'udp' in dir(packet):
                self.if_add_server(packet.ip.src, packet.udp.srcport)
                self.if_add_server(packet.ip.dst, packet.udp.dstport)


    def pretty_print(self):
        string = "Servers from cap:\n"
        for ip, servers in self._dict.items():
            if self.defined_only:
                servers = [server for server in servers if not "Not Defined" in server]
            string += "{ip}: {servers}.\n".format(ip=ip, servers=", ".join(servers))
        print(string)


def main():
    pass


if __name__ == '__main__':
    main()