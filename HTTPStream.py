import Files
from datetime import datetime
from PacketCapture import PacketCapture



HTTP_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
FILE_DATE_FORMAT = '%Y-%m-%d %H-%M-%S'
HTML_FILE_FORMAT = """Client IP - {client_ip}<br>
Server IP - {server_ip}<br>
Client Port - {client_port}<br>
Host - {host}<br>
User Agent - {user_agent}<br>
Date - {date}<br>
Form - {form}<br><br>
{html}
"""


class HTTPStream(object):
    def __init__(self, packet):
        self.client_ip = packet.ip.src
        self.server_ip = packet.ip.dst
        self.client_port = packet.tcp.srcport
        self.host = packet.http.host if hasattr(packet.http, "host") else None
        self.user_agent = packet.http.user_agent if hasattr(packet.http, "user_agent") else None

        if packet.highest_layer == 'URLENCODED-FORM':
            form_layer = getattr(packet, 'urlencoded-form')
            key, value = form_layer.key, form_layer.value
            self.form = "{key}={value}".format(key=key, value=value)
        else:
            self.form = None

        self.date = None
        self.html = None   


    def append(self, packet):
        if packet.highest_layer == 'DATA-TEXT-LINES':
            date = datetime.strptime(packet.http.date, HTTP_DATE_FORMAT)
            self.date = date.strftime(FILE_DATE_FORMAT)
            self.html = extract_html(packet)

 
    def export(self, directory):
        attributes = {"client_ip": self.client_ip, "server_ip": self.server_ip, "client_port": self.client_port, "host": self.host, "html": self.html,\
                      "user_agent": self.user_agent, "date": self.date, "form": self.form}

        text = HTML_FILE_FORMAT.format(**attributes)
        host = self.host
        ip = self.client_ip

        Files.safe_makedirs(directory + ip)
        directory += ip + "\\"
        path = directory + "{host} {date}.html".format(host=host, date=self.date)

        with open(path, 'w') as f:
            f.write(text)


    def pretty_print(self):
        print("{ip} ({date}) - {host}".format(ip=self.client_ip, date=self.date, host=self.host))


class Parser(PacketCapture):
    def __init__(self, directory, cap=None):
        super().__init__(cap)
        self.http_streams = []
        self.directory = directory


    def __exit__(self):
        pass


    def parse(self, packet):
        if 'http' in dir(packet):
            if hasattr(packet.http, 'request_method') and packet.http.request_method in ['POST', 'GET']:
                self.http_streams += [HTTPStream(packet)]

            if packet.highest_layer == 'DATA-TEXT-LINES':
                for stream in self.http_streams:
                    if stream.client_port == packet.tcp.dstport and stream.html is None:
                        stream.append(packet)
                        stream.export(self.directory)
                        stream.pretty_print()


def extract_html(packet):
    data_layer = getattr(packet, "data-text-lines")
    html = ''.join(data_layer._get_all_field_lines())
    return html.replace('\\n', '').replace('\\r', '')


def main():
    pass
    

if __name__ == '__main__':
    main()