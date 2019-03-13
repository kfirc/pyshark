__author__ = 'Kfir'

def coroutine(func):
    def start(*args,**kwargs):
        cr = func(*args,**kwargs)
        next(cr)
        return cr
    return start


class PacketCapture(object):
    def __init__(self, cap=None):
        if cap is not None:
            for packet in cap:
                self.parse(packet)
        else:
            self.capture = self._capture()

    @coroutine
    def _capture(self):
        try:
            while True:
                packet = (yield)
                self.parse(packet)
        except GeneratorExit:
            self.__exit__()

    def __next__(self):
        if hasattr(self, 'capture'):
            next(self.capture)

    def __exit(self):
        raise NotImplementedError

    def send(self, packet):
        if hasattr(self, 'capture'):
            self.capture.send(packet)

    def close(self):
        if hasattr(self, 'capture'):
            self.capture.close()

    def parse(self, *args, **kwargs):
        raise NotImplementedError


def main():
    pass


if __name__ == "__main__":
    main()
