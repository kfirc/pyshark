import pyshark
from datetime import datetime

DIRECTORY = 'C:\\Users\\Kfir\\Desktop\\git\\assigments\\TD\\'
CAP_URL = DIRECTORY + "GENERAL_HackChallenge_Cmas2011_CounterHack.pcap"
TEST_PATH = DIRECTORY + "test.html"

HTTP_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
FILE_DATE_FORMAT = '%Y-%m-%d %H:%M'
HTML_FILE_FORMAT = """client_ip - {client_ip}
client_port - {client_port}
host - {host}
pkt_numbers - {pkt_numbers}
user_agent - {user_agent}
date - {date}

{html}
"""


class HTTP_Stream(object):
    def __init__(self, client_ip, client_port, host, pkt_number, user_agent=None, html=None, date=None):
        self.html = html
        self.user_agent = user_agent
        self.host = host
        self.pkt_numbers = [pkt_number]
        self.client_port = client_port
        self.client_ip = client_ip


def parse_html(cap):
    
    http_streams = []

    for i, packet in enumerate(cap):
        if packet.highest_layer == 'HTTP':
            if hasattr(packet.http, 'request_method') and packet.http.request_method in ['POST', 'GET']:
                host = packet.http.host
                client_ip = packet.ip.src
                client_port = packet.tcp.srcport
                user_agent = packet.http.user_agent
                http_streams.append(HTTP_Stream(client_ip, client_port, host, str(i), user_agent))

        if packet.highest_layer == 'DATA-TEXT-LINES':
            client_port = packet.tcp.dstport
            date = datetime.strptime(packet.http.date, HTTP_DATE_FORMAT)
            date = date.strftime(FILE_DATE_FORMAT)
            data_layer = getattr(packet, "data-text-lines")
            html_generator = data_layer._get_all_field_lines()
            html = ""

            for part in html_generator:
                html += part

            for stream in http_streams:
                if stream.client_port == client_port and stream.html is None:
                    stream.html = html
                    stream.date = date
                    stream.pkt_numbers.append(str(i))

    for stream in http_streams:
        if stream.html:

            attributes = {"client_ip": stream.client_ip, "client_port": stream.client_port, "host": stream.host, "html": stream.html,\
                          "pkt_numbers": ",".join(stream.pkt_numbers), "user_agent": stream.user_agent, "date": stream.date}

            text = HTML_FILE_FORMAT.format(**attributes)
            path = DIRECTORY + "{host} {date}.html".format(host=stream.host, date=stream.date)
            print(path)
            print(text)
            print("****************************")
            with open(path, 'w') as f:
                f.write(text)


def main():
    cap = pyshark.FileCapture(CAP_URL)
    parse_html(cap)


if __name__ == '__main__':
	main()