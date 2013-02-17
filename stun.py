# coding: utf-8
import random
import socket
import binascii
import struct
import argparse

STUN_PORT = 3478

FAMILY_IPv4 = '\x01'
FAMILY_IPv6 = '\x02'

# 0b00: Request
# 0b01: Binding
BINDING_REQUEST_SIGN = '\x00\x01' # 16bit (2bytes)

BINDING_RESPONSE_ERROR = '\x01\x11'
BINDING_RESPONSE_SUCCESS = '\x01\x01'
MAGIC_COOKIE = '\x21\x12\xA4\x42' # 固定値 32bit (4bytes)

# STUN Attribute Registry
MAPPED_ADDRESS = '\x00\x01'
RESPONSE_ADDRESS = '\x00\x02'
CHANGE_REQUEST = '\x00\x03'
SOURCE_ADDRESS = '\x00\x04'
CHANGED_ADDRESS = '\x00\x05'
USERNAME = '\x00\x06'
PASSWORD = '\x00\x07'
MESSAGE_INTEGRITY = '\x00\x08'
ERROR_CODE = '\x00\x09'
UNKNOWN_ATTRIBUTES = '\x00\x0A'
REFLECTED_FROM = '\x00\x0B'
REALM = '\x00\x14'
NONCE = '\x00\x15'
XOR_MAPPED_ADDRESS = '\x80\x82'

STUN_ATTRIBUTE_NAMES = {
    MAPPED_ADDRESS: 'MAPPED-ADDRESS',
    RESPONSE_ADDRESS: 'RESPONSE-ADDRESS',
    CHANGE_REQUEST: 'CHANGE-REQUEST',
    SOURCE_ADDRESS: 'SOURCE-ADDRESS',
    CHANGED_ADDRESS: 'CHANGED-ADDRESS',
    USERNAME: 'USERNAME',
    PASSWORD: 'PASSWORD',
    MESSAGE_INTEGRITY: 'MESSAGE-INTEGRITY',
    ERROR_CODE: 'ERROR-CODE',
    UNKNOWN_ATTRIBUTES: 'UNKNOWN-ATTRIBUTES',
    REFLECTED_FROM: 'REFLECTED-FROM',
    REALM: 'REALM',
    NONCE: 'NONCE',
    XOR_MAPPED_ADDRESS: 'XOR-MAPPED-ADDRESS',
    '\x00\x20': 'XOR-MAPPED-ADDRESS',
}


socket.setdefaulttimeout(10)


def generate_transaction_id():
    tid = []
    for i in xrange(24): # 96bits (12bytes)
        tid.append(random.choice('0123456789ABCDEF'))
    return binascii.a2b_hex(''.join(tid))


def build_binding_request(transaction_id):
    if len(transaction_id) != 12:
        raise RuntimeError('Invalid transaction id')

    body_length = '\x00\x00' # 属性無しなので0。 16bit (2bytes)
    return ''.join([BINDING_REQUEST_SIGN, body_length, MAGIC_COOKIE, transaction_id])


def validate_response(buf, transaction_id):
    if not buf or len(buf) < 20:
        raise RuntimeError('Response too shoot')

    response_sign = buf[:2]
    if response_sign != BINDING_RESPONSE_SUCCESS:
        if response_sign == BINDING_RESPONSE_ERROR:
            raise RuntimeError('BINDING_RESPONSE_ERROR')
        raise RuntimeError('Invalid Response')

    response_magic_cookie = buf[4:8]
    if MAGIC_COOKIE != response_magic_cookie:
        raise RuntimeError('Invalid magic cookie')

    response_transaction_id = buf[8:20]
    if transaction_id != response_transaction_id:
        raise RuntimeError('invalid transaction id')


def ip_to_bytes(ip, xor):
    octets = [binascii.a2b_hex('%02x' % int(o)) for o in ip.split('.')]
    addr_int = struct.unpack('!I', ''.join(octets))[0]

    if xor:
        magicCookieBytesInt = int(binascii.b2a_hex(MAGIC_COOKIE), 16)
        addr_int = magicCookieBytesInt ^ addr_int

    addr_bytes = binascii.a2b_hex('%08x' % addr_int)
    return addr_bytes


def port_to_bytes(port, xor):
    if xor:
        magicCookieHighBytesInt = int(binascii.b2a_hex(MAGIC_COOKIE[:2]), 16)
        port = magicCookieHighBytesInt ^ port

    port_bytes = binascii.a2b_hex('%04x' % port)
    return port_bytes


def read_mapped_address(attr_type, attr_body, attr_len):
    assert attr_type in (MAPPED_ADDRESS, XOR_MAPPED_ADDRESS, '\x00\x20')
    assert attr_body[:1] == '\x00' # 最初の 8bit (1bytes) は 0 に設定しなければならない

    family_bytes = attr_body[1:2]
    port_bytes = attr_body[2:4]
    addr_bytes = attr_body[4:attr_len]
    xor = attr_type in (XOR_MAPPED_ADDRESS, '\x00\x20')

    family_text = ''
    assert family_bytes in (FAMILY_IPv4, FAMILY_IPv6)
    if family_bytes == FAMILY_IPv4:
        family_text = 'IPv4'
    elif family_bytes == FAMILY_IPv6:
        family_text = 'IPv6'

    # TODO: IPv6 に対応
    port = int(binascii.b2a_hex(port_bytes), 16)
    addr_int = int(binascii.b2a_hex(addr_bytes), 16)

    if xor:
        # port
        magicCookieHighBytesInt = int(binascii.b2a_hex(MAGIC_COOKIE[:2]), 16)
        port =  magicCookieHighBytesInt ^ port

        # addr
        magicCookieBytesInt = int(binascii.b2a_hex(MAGIC_COOKIE), 16)
        addr_int =  magicCookieBytesInt ^ addr_int

    octets = struct.pack('!I', addr_int)
    ip = '.'.join([str(ord(c)) for c in octets])
    return dict(name=STUN_ATTRIBUTE_NAMES[attr_type], ip=ip, port=port, family=family_text)


def read_attributes(attributes, body_length):
    pos = 0
    parsed_attributes = []
    while pos < body_length:
        attr_type = attributes[pos:pos + 2] # 16bit (2bytes)
        attr_len = int(binascii.b2a_hex(attributes[pos + 2:pos + 4]), 16) # 16bit (2bytes)
        attr_body = attributes[pos + 4:pos + 4 + attr_len]

        if attr_type in (MAPPED_ADDRESS, XOR_MAPPED_ADDRESS, '\x00\x20'):
            parsed_attributes.append(read_mapped_address(attr_type, attr_body, attr_len))
        else:
            parsed_attributes.append(dict(
                name=STUN_ATTRIBUTE_NAMES.get(attr_type),
                attr_type=attr_type,
                attr_body=attr_body,
                attr_len=attr_len
            ))

        attr_head = (2 + 2) # attr_type + attr_len
        remain = attr_len % 4
        # 32bit 境界 (4bytes区切り) でない場合、詰め物有り
        padding = 4 - remain if remain else 0
        pos += attr_head + attr_len + padding

    return parsed_attributes


class StunClient(object):
    def __init__(self):
        self.sock = None
        self.transaction_id = None
        self.req = None

    def send_request(self, host, port=STUN_PORT):
        self.transaction_id = generate_transaction_id()
        self.req = build_binding_request(self.transaction_id)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 0))

        self.sock.sendto(self.req, (host, port))


    def receive_response(self):
        buf, addr = self.sock.recvfrom(2048)
        validate_response(buf, self.transaction_id)

        body_length = int(binascii.b2a_hex(buf[2:4]), 16)
        attributes = buf[20:]
        # body_length と実際の attribules の長さは一致するはず
        assert len(attributes) == body_length

        return read_attributes(attributes, body_length)

    def close(self):
        if self.sock:
            self.sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, help='Stun server host name')
    parser.add_argument('--port', type=int, help='Stun server port', nargs='?', default=STUN_PORT)

    args = parser.parse_args()

    client = StunClient()
    client.send_request(args.host, args.port)
    print client.receive_response()
    client.close()

