from PacketCapture import PacketCapture

__author__ = 'Kfir'

class Hops(PacketCapture):
    def __init__(self, cap=None):
        self._list = []
        super().__init__(cap)

        if cap:
            self.pretty_print()


    def __exit__(self):
        self.pretty_print()


    def parse(self, packet):
        if 'ip' in dir(packet):
            ttl = int(packet.ip.ttl)
            hops = 32 - ((ttl - 1) % 32 + 1)
            if ttl < 129 and 0 <= hops <= 10:
                self._list = list(set(self._list).union([(packet.ip.src, hops)]))


    def pretty_print(self):
        print("Hops per IP:")
        for ip, hops in self._list:
            print("{ip} - {hops} hops away".format(ip=ip, hops=hops))


def main():
    pass


if __name__ == "__main__":
    main()