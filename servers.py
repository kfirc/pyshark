import pyshark

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


class Servers(object):
    def __init__(self, cap=None):
        self._dict = {}
        if cap is not None: self.find(cap)


    def if_add_server(self, ip, port):
        server_name = self.name(port)
        if server_name:
            self.add(ip, server_name)


    def name(self, port):
        if port in SERVER_PORTS.keys():
            return SERVER_PORTS[port]
        elif 0 < int(port) < 1024:
            return "port {port} (Not Defined)".format(port=port)
        return None


    def add(self, ip, server_name):
        if not ip in self._dict.keys():
            self._dict[ip] = []
        self._dict[ip] = list(set(self._dict[ip]).union([server_name]))


    def find(self, cap):
        for packet in cap:
            if 'ip' in dir(packet):
                if 'tcp' in dir(packet):
                    self.if_add_server(packet.ip.src, packet.tcp.srcport)
                    self.if_add_server(packet.ip.dst, packet.tcp.dstport)
                if 'udp' in dir(packet):
                    self.if_add_server(packet.ip.src, packet.udp.srcport)
                    self.if_add_server(packet.ip.dst, packet.udp.dstport) 


    def pretty_print(self, defined_only=False):
        string = "Servers from cap:\n"
        for ip, servers in self._dict.items():
            if defined_only:
                servers = [server for server in servers if not "Not Defined" in server]
            string += "{ip}: {servers}.\n".format(ip=ip, servers=", ".join(servers))
        print(string)                


def pretty_print(cap, defined_only=False):
    network_servers = Servers(cap)
    network_servers.pretty_print(defined_only)


def main():
    pass


if __name__ == '__main__':
    main()