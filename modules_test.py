import servers
import files
import address_map
import http_stream
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


def diagnose_network(cap, directory=DIRECTORY):
    address_map.pretty_print(cap)
    servers.pretty_print(cap)
    http_stream.parse_html(cap, directory)
    #files.decode_base64(ATTACHMENT_URL, DECODED_ATTACHMENT_URL)    


def main():
    filecap = pyshark.FileCapture(CAP_URL)
    #livecap = live_capture(packet_count=10)
    diagnose_network(filecap)


if __name__ == '__main__':
    main()