import Servers
import Files
import AddressMap
import HTTPStream
from Hops import Hops
import pyshark


DIRECTORY = 'C:\\Users\\Kfir\\Desktop\\git\\assigments\\TD\\' #"C:\\Users\\Lilya\\Desktop\\kfir\\test\\"
CAP_URL = DIRECTORY + "GENERAL_HackChallenge_Cmas2011_CounterHack.pcap"
TEST_PATH = DIRECTORY + "test.html"
ATTACHMENT_URL = DIRECTORY + "attachment.txt"
DECODED_ATTACHMENT_URL = DIRECTORY + "decoded_attachment.doc"


def packet_captured(packet):
    print('Just arrived:', packet.highest_layer)


def live_capture(interface=None, capture_filter=None, packet_count=None):
    cap = pyshark.LiveCapture(interface=interface, capture_filter=capture_filter)
    cap.sniff(packet_count=packet_count)
    return cap


def analyze_cap(cap, directory=DIRECTORY):
    map_address = AddressMap.IPtoMAC()
    cap_servers = Servers.CaptureServers()
    parse_html = HTTPStream.Parser(directory)
    hops = Hops()
    for i, packet in enumerate(cap):
        map_address.send(packet)
        cap_servers.send(packet)
        parse_html.send((packet, i))
        hops.send(packet)
    map_address.close()
    cap_servers.close()
    parse_html.close()
    hops.close()
    #Files.decode_base64(ATTACHMENT_URL, DECODED_ATTACHMENT_URL)    


def main():
    file_cap = pyshark.FileCapture(CAP_URL)
    #live_cap = live_capture(packet_count=100)
    analyze_cap(file_cap)


if __name__ == '__main__':
    main()