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
	def __init__(self):
		self._dict = {}


	def if_add_server(self, ip, port):
		server_name = self.name(ip, port)
		if server_name:
			self.add(ip, server_name)


	def name(self, ip, port):
		if port in SERVER_PORTS.keys():
			return SERVER_PORTS[port]
		elif 0 < int(port) < 1024:
			return "port {port} (Not Defined)".format(port=port)
		return None


	def add(self, ip, server_name):
		if not ip in self._dict.keys():
			self._dict[ip] = []
		self._dict[ip] = list(set(self._dict[ip]).union([server_name]))


def find(cap):
	servers = Servers()
	for packet in cap:
		if 'ip' in dir(packet):
			if 'tcp' in dir(packet):
				servers.if_add_server(packet.ip.src, packet.tcp.srcport)
				servers.if_add_server(packet.ip.dst, packet.tcp.dstport)
			if 'udp' in dir(packet):
				servers.if_add_server(packet.ip.src, packet.udp.srcport)
				servers.if_add_server(packet.ip.dst, packet.udp.dstport)

	return servers._dict				


def pretty_print(cap):
	network_servers = find(cap)
	string = "Servers from cap:\n"
	for ip, servers in network_servers.items():
		string += "{ip}: {servers}.\n".format(ip=ip, servers=", ".join(servers))
	print(string)


def main():
	pass


if __name__ == '__main__':
	main()