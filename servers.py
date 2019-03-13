from PacketCapture import PacketCapture

__author__ = 'Kfir'
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


class CaptureServers(PacketCapture):
    def __init__(self, cap=None, defined_only=False):
        super().__init__(cap)
        self._dict = {}
        self.defined_only = defined_only

        if cap: self.pretty_print()


    def __exit__(self):
        self.pretty_print()


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


    def parse(self, packet):
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