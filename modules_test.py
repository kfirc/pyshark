import servers
import files
import address_map
import http_stream
import pyshark


DIRECTORY = 'C:\\Users\\Kfir\\Desktop\\git\\assigments\\TD\\'
CAP_URL = DIRECTORY + "GENERAL_HackChallenge_Cmas2011_CounterHack.pcap"
TEST_PATH = DIRECTORY + "test.html"
ATTACHMENT_URL = DIRECTORY + "attachment.txt"
DECODED_ATTACHMENT_URL = DIRECTORY + "decoded_attachment.doc"

def packet_captured(packet):
    print('Just arrived:', packet)


def live_capture(interface=None, capture_filter=None):
    capture = pyshark.LiveCapture(interface=interface, capture_filter=capture_filter)
    capture.apply_on_packets(packet_captured)


def file_capture(cap_url):
    cap = pyshark.FileCapture(cap_url)
    address_map.pretty_print(cap)
    servers.pretty_print(cap)
    http_stream.parse_html(cap, "C:\\Users\\Kfir\\Desktop\\test\\")
    #files.decode_base64(ATTACHMENT_URL, DECODED_ATTACHMENT_URL)    


def main():
    live_capture()
    #file_capture(CAP_URL)


if __name__ == '__main__':
    main()