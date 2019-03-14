import sys
import Servers
import Files
import AddressMap
import HTTPStream
from Hops import Hops
import pyshark


DIRECTORY = 'C:\\Users\\Kfir\\Desktop\\assigments\\TD\\' #"C:\\Users\\Lilya\\Desktop\\kfir\\test\\"
CAP_URL = "GENERAL_HackChallenge_Cmas2011_CounterHack.pcap"
ATTACHMENT_URL = DIRECTORY + "attachment.txt"
DECODED_ATTACHMENT_URL = DIRECTORY + "decoded_attachment.doc"


def packet_captured(packet):
    print('Just arrived:', packet.highest_layer)


def live_capture(interface=None, capture_filter=None, packet_count=None):
    cap = pyshark.LiveCapture(interface=interface, capture_filter=capture_filter)
    cap.sniff(packet_count=packet_count)
    return cap


def analyze_cap(cap, directory):
    tasks = (AddressMap.IPtoMAC(), Servers.CaptureServers(), HTTPStream.Parser(directory), Hops())
    for packet in cap:
        for task in tasks:
            task.send(packet)
    close_task = lambda tsk: tsk.close()
    map(close_task, tasks)


def main(cap_url=CAP_URL, directory=DIRECTORY):
    file_cap = pyshark.FileCapture(cap_url)
    analyze_cap(file_cap, directory)
    #Files.decode_base64(ATTACHMENT_URL, DECODED_ATTACHMENT_URL)


if __name__ == '__main__':
    main(*sys.argv[1:])