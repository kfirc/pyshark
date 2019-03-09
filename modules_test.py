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


def test():
    cap = pyshark.FileCapture(CAP_URL)
    address_map.pretty_print(cap)
    servers.pretty_print(cap)
    #http_stream.parse_html(cap, "C:\\Users\\Kfir\\Desktop\\test\\")
    #files.decode_base64(ATTACHMENT_URL, DECODED_ATTACHMENT_URL)    


def main():
    test()


if __name__ == '__main__':
    main()