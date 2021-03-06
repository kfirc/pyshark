from PacketCapture import PacketCapture

__author__ = 'Kfir'
UNKNOWN_MAC = '00:00:00:00:00:00'


class IPtoMAC(PacketCapture):
    def __init__(self, cap=None):
        super().__init__(cap)
        self.address_map = {UNKNOWN_MAC: []}

        if cap: self.pretty_print()


    def __exit__(self):
        self.pretty_print()


    def parse(self, packet):
        if packet.highest_layer == 'ARP':
            self._map_arp(packet)
        elif 'ip' in dir(packet) and "eth" in dir(packet):
            self._map_ip(packet)


    def _map_arp(self, packet):
        sender = (packet.arp.src_hw_mac, packet.arp.src_proto_ipv4)
        target = (packet.arp.dst_hw_mac, packet.arp.dst_proto_ipv4)

        self._append_to_dict(sender[0], sender[1])

        if not (target[0] == UNKNOWN_MAC and self._ip_exist(target[1])):
            self._append_to_dict(target[0], target[1])


    def _ip_exist(self, ip):
        for ips in self.address_map.values():
            if ip in ips:
                return True
        return False


    def _map_ip(self, packet):
        sender = (packet.eth.src, packet.ip.src)
        target = (packet.eth.dst, packet.ip.dst)

        self._append_to_dict(sender[0], sender[1])
        self._append_to_dict(target[0], target[1])        


    def _set_dict_value(self, key, value):
        print(self.address_map[key])
        if isinstance(value, list):
            self.address_map[key] = value
        else:
            self.address_map[key] = list([value])
        print(self.address_map[key])


    def _append_to_dict(self, key, value):
        if not key in self.address_map.keys():
            if value in self.address_map[UNKNOWN_MAC]:
                self.address_map[UNKNOWN_MAC].remove(value)
            self.address_map[key] = [value]
        else:
            self.address_map[key] = list(set(self.address_map[key]).union([value]))


    def pretty_print(self):
        string = "MAC to IP address map from cap:\n"
        for mac, ips in self.address_map.items():
            if ips:
                string += "{mac}: {ips}\n".format(mac=mac,ips=", ".join(ips))
        print(string)
            

def main():
    pass


if __name__ == '__main__':
    main()

