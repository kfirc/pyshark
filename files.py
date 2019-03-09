import base64
import os


def safe_makedirs(path):
    if not os.path.exists(path):
        os.makedirs(path)


def decode_base64(path, to_path=None):
    with open(path, 'rb') as file_from:
        text = file_from.read()

    text = base64.b64decode(text)

    with open(to_path if to_path else path, 'wb') as file_to:
        file_to.write(text)


def main():
    pass


if __name__ == '__main__':
    main()