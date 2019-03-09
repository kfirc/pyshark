import files
import pyshark
from datetime import datetime


HTTP_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
FILE_DATE_FORMAT = '%Y-%m-%d %H-%M-%S'
HTML_FILE_FORMAT = """Client IP - {client_ip}<br>
Server IP - {server_ip}<br>
Client Port - {client_port}<br>
Host - {host}<br>
Packet Numbers - {pkt_numbers}<br>
User Agent - {user_agent}<br>
Date - {date}<br>
Form - {form}<br><br>
{html}
"""

class HTTP_Stream(object):
    def __init__(self, packet, pkt_number=None):
        self.host = packet.http.host
        self.client_ip = packet.ip.src
        self.server_ip = packet.ip.dst
        self.client_port = packet.tcp.srcport
        self.user_agent = packet.http.user_agent

        if packet.highest_layer == 'URLENCODED-FORM':
            form_layer = getattr(packet, 'urlencoded-form')
            key, value = form_layer.key, form_layer.value
            self.form = "{key}={value}".format(key=key, value=value)
        else:
            self.form = None

        self.pkt_numbers = [pkt_number]
        self.date = None
        self.html = None   


    def export(self, directory):
        attributes = {"client_ip": self.client_ip, "server_ip": self.server_ip, "client_port": self.client_port, "host": self.host, "html": self.html,\
                      "pkt_numbers": ",".join(self.pkt_numbers), "user_agent": self.user_agent, "date": self.date, "form": self.form}

        text = HTML_FILE_FORMAT.format(**attributes)
        host = self.host.replace('.', '(d)')
        ip = self.client_ip.replace('.', '-')

        files.safe_makedirs(directory + ip)
        directory += ip + "\\"
        path = directory + "{host} {date}.html".format(host=host, date=self.date)

        with open(path, 'w') as f:
            f.write(text)


def extract(packet):
    data_layer = getattr(packet, "data-text-lines")
    html = ''.join(data_layer._get_all_field_lines())
    return html.replace('\\n', '').replace('\\r', '')


def parse_html(cap, directory):
    
    http_streams = []

    for i, packet in enumerate(cap):
        if 'http' in dir(packet):
            if hasattr(packet.http, 'request_method') and packet.http.request_method in ['POST', 'GET']:
                pkt_number = str(i+1)
                stream = HTTP_Stream(packet, pkt_number)
                http_streams.append(stream)

        if packet.highest_layer == 'DATA-TEXT-LINES':
            client_port = packet.tcp.dstport
            date = datetime.strptime(packet.http.date, HTTP_DATE_FORMAT)
            date = date.strftime(FILE_DATE_FORMAT)
            html = extract(packet)
            
            for stream in http_streams:
                if stream.client_port == client_port and stream.html is None:
                    stream.html = html
                    stream.date = date
                    stream.pkt_numbers.append(str(i+1))

    for stream in http_streams:
        if stream.html:
            stream.export(directory)


def main():
    pass
    

if __name__ == '__main__':
    main()