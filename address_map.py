import pyshark
from datetime import datetime

DIRECTORY = 'C:\\Users\\Kfir\\Desktop\\git\\assigments\\TD\\'
CAP_URL = DIRECTORY + "GENERAL_HackChallenge_Cmas2011_CounterHack.pcap"

UNKNOWN_MAC = '00:00:00:00:00:00'


class Address_Map(object):
    def __init__(self, cap):
        self.address_map = {UNKNOWN_MAC: []}
        self.create_map(cap)


    def create_map(self, cap):
        for packet in cap:
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
        for mac in self.address_map.keys():
            if self.address_map[mac]:
                ips = ", ".join(self.address_map[mac])
                print("{mac}: {ips}".format(mac=mac,ips=ips))


def address_map(cap):
    cap_map = Address_Map(cap)
    cap_map.pretty_print()
            

def main():
    cap = pyshark.FileCapture(CAP_URL)
    address_map(cap)
    

if __name__ == '__main__':
    main()

