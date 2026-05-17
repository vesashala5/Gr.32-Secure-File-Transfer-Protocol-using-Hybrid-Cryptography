import struct

CHUNK = 4096
TAG_SIZE = 16
HEADER_SIZE = 4


def recv_all(sock, size):
    """
    Receives exactly 'size' bytes from the socket.
    This avoids incomplete reads from the network.
    """
    data = b''

    while len(data) < size:
        packet = sock.recv(size - len(data))

        if not packet:
            raise ConnectionError("Connection closed unexpectedly.")

        data += packet

    return data


def send_msg(sock, tag, data=b''):
    """
    Sends a message using this format:
    16 bytes tag + 4 bytes data length + data
    """
    tag = tag.encode().ljust(TAG_SIZE)
    size = struct.pack("!I", len(data))
    sock.sendall(tag + size + data)


def recv_msg(sock):
    """
    Receives a message using this format:
    16 bytes tag + 4 bytes data length + data
    """
    tag = recv_all(sock, TAG_SIZE).strip().decode()
    size = struct.unpack("!I", recv_all(sock, HEADER_SIZE))[0]
    data = recv_all(sock, size)

    return tag, data