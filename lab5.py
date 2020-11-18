import hashlib
import socket
import struct
from time import strftime, gmtime
import time

PEER_HOST = '94.52.112.227'
PEER_PORT = 8333
HDR_SZ = 24
BUFF_SZ = 2048
TARGET = 160504  # 4060504 % 650000
NUM_PER_IT = 500
# TARGET = 475
TOTAL_ITERATIONS = TARGET / NUM_PER_IT


def check_sum(n):
    return hashlib.sha256(hashlib.sha256(n).digest()).digest()[:4]


def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)


def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])


def bool_t(flag):
    return uint8_t(1 if flag else 0)


def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))


def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])


def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)


def uint16_t(n):
    return int(n).to_bytes(2, byteorder='little', signed=False)


def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)


def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)


def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)


def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)


def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)


def unmarshal_uint(b):
    return int.from_bytes(b, byteorder='little', signed=False)


def print_message(msg, text=None, iteration=0):
    """
    Report the contents of the given bitcoin message
    :param msg: bitcoin message including header
    :return: message type
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg),
                           msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[HDR_SZ:]
    command = print_header(msg[:HDR_SZ], check_sum(payload))

    highest = ''
    found = False

    if command == 'version':
        print_version_msg(payload)
    elif command == 'inv':
        highest, found = print_inv_msg(payload, iteration)
    elif command == 'block':
        print_block_msg(payload)
    return command, highest, found


def print_block_msg(b):
    print('BLOCK HEADER')
    print('--------------------------------------------------------------------'
          '--------------------------------')

    prefix = '  '

    version = b[:4]
    prev_header_hash = convertLittletoBig(b[4:36].hex())
    merkle_root_hash = convertLittletoBig(b[36:68].hex())
    unix_time = b[68:72]
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT",
                        gmtime(unmarshal_int(unix_time)))
    nbits = convertLittletoBig(b[72:76].hex())
    nonce = convertLittletoBig(b[76:80].hex())

    print('{}{:80} version {}'.format(prefix, version.hex(),
                                      unmarshal_int(version)))
    print('{}{:80} Previous Header Hash'.format(prefix, prev_header_hash))
    print('{}{:80} Merkle Root Hash'.format(prefix, merkle_root_hash))
    print('{}{:80} epoch time {}'.format(prefix, unix_time.hex(), time_str))
    print('{}{:80} nbits'.format(prefix, nbits))
    print('{}{:80} nonce'.format(prefix, nonce))

    split = b[80:].split(bytes.fromhex('01000000'))
    key, count = unmarshal_compactsize(split[0])

    print('TRANSACTIONS')
    print(
        '--------------------------------------------------------------------'
        '--------------------------------')
    print('{}{:80} Transaction Count {}'.format(prefix, key.hex(), count))


def print_inv_msg(b, iteration):
    if iteration == 0 or TOTAL_ITERATIONS - iteration < 2:
        print('INV')
        print(
            '-----------------------------------------------------------------'
            '-----------------------------------')
        print(b[:3].hex(),
              '   (each hash printed in reverse of serialized order for clarity'
              ')   count 500')
    count = 1
    iterationStart = iteration * 500
    numBytes = 36
    remainder = ''
    for i in range(3, len(b), numBytes):
        try:
            block = b[i:i + numBytes].hex()
            starter = block[:8]
            remainder = convertLittletoBig(block[8:])
            if iterationStart + count == TARGET:
                print(starter, remainder, 'MSG_BLOCK',
                      'inventory #' + str(iterationStart + count))
                return remainder, True
            if iteration == 0 or TOTAL_ITERATIONS - iteration < 2:
                print(starter, remainder, 'MSG_BLOCK',
                      'inventory #' + str(iterationStart + count))
            count += 1
        except Exception:
            continue
    return remainder, False


def convertLittletoBig(string):
    t = bytearray.fromhex(string)
    t.reverse()
    return ''.join(format(x, '02x') for x in t)


def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], \
                                                      b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], \
                                                         b[46:54], b[54:70], \
                                                         b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(),
                                      unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT",
                        gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(),
                                        ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(),
                                        unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(),
                                      ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(),
                                      unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(),
                                              uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(),
                                             str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(),
                                           unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))


def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if
                            known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], \
                                              header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]),
                  encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command


class Lab5(object):

    def __init__(self):
        self.listener, self.listener_address = self.start_listener()

    @staticmethod
    def start_listener():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('', 0))
        return listener, listener.getsockname()

    def run(self):
        self.listener.connect((PEER_HOST, PEER_PORT))

        versionPayload = self.construct_version_payload()
        versionHeader = self.construct_header(versionPayload, 'version')
        versionMsg = versionHeader + versionPayload

        self.process_message(versionMsg)

        verack = self.construct_header(''.encode(), 'verack')

        self.process_message(verack)

        getblocksPayload = self.construct_getblocks_payload(True)
        getblocksHeader = self.construct_header(getblocksPayload, 'getblocks')
        getblocksMsg = getblocksHeader + getblocksPayload

        highest_inv, found = self.process_message(getblocksMsg, 'getblocks')

        highest_inv = self.find_my_block(highest_inv, found)

        getdataPayload = self.construct_getdata_payload(highest_inv)
        getdataHeader = self.construct_header(getdataPayload, 'getdata')
        getdataMsg = getdataHeader + getdataPayload

        self.process_message(getdataMsg, 'getdata')

    def find_my_block(self, highest_inv, found):
        iteration = 1
        while not found:
            getblocksPayload = self.construct_getblocks_payload(False,
                                                                highest_inv)
            getblocksHeader = self.construct_header(getblocksPayload,
                                                    'getblocks')
            getblocksMsg = getblocksHeader + getblocksPayload

            highest_inv, found = self.process_message(getblocksMsg, 'getblocks',
                                                      iteration)

            iteration += 1
        return highest_inv

    # my hash: 000000000000058a4a53582cde13ea4565bda6741ef64556d34a9515c4700e76
    def construct_getdata_payload(self, block_hash):
        count = compactsize_t(1)

        block = bytearray.fromhex(convertLittletoBig(block_hash))

        hashType = uint32_t(2)

        payload = count + hashType + block

        return payload

    def construct_getblocks_payload(self, initial, highest=''):
        version = int32_t(70015)
        hashCount = compactsize_t(1)

        if initial:
            blockHeaderHashes = struct.pack("32s", b'\x00')
        else:
            blockHeaderHashes = bytearray.fromhex(convertLittletoBig(highest))

        stopHash = struct.pack("32s", b'\x00')

        payload = version + hashCount + blockHeaderHashes + stopHash

        return payload

    def process_message(self, message, command='', iteration=0):
        print_message(message, 'Sending')
        self.listener.send(message)
        received = self.listener.recv(BUFF_SZ)
        processedMessages = self.split_message(received)
        check, msg, highest, found = '', '', '', False

        for msg in processedMessages:
            payload = msg[HDR_SZ:]
            checksum = check_sum(payload)
            header = msg[:HDR_SZ]
            headerChecksum = header[20:]

            while checksum != headerChecksum:
                if checksum == headerChecksum:
                    break
                else:
                    addMsg = self.listener.recv(BUFF_SZ)
                    splitMsg = addMsg.hex().partition('f9beb4d9')

                    payload += bytes.fromhex(splitMsg[0])
                    processedMessages.extend(self.split_message(
                        bytes.fromhex(splitMsg[2])))
                    checksum = check_sum(payload)
            check, highest, found = print_message(header + payload, 'Received',
                                                  iteration)
            # print('the highest inv is', highest)
        if command == 'getblocks':
            if check != 'inv':
                return self.process_message(msg, command)

        return highest, found

    @staticmethod
    def split_message(message):
        allMessages = message.hex()
        messageArr = allMessages.split('f9beb4d9')
        fullyParsedMessage = []
        for i in range(1, len(messageArr)):
            encodedMessage = bytes.fromhex('f9beb4d9' + messageArr[i])
            fullyParsedMessage.append(encodedMessage)
        return fullyParsedMessage

    @staticmethod
    def construct_header(payload, command):
        magic = bytearray.fromhex("F9BEB4D9")
        command = struct.pack("12s", command.encode())
        length = uint32_t(len(payload))
        checksum = check_sum(payload)

        header = magic + command + length + checksum

        return header

    def construct_version_payload(self):
        version = int32_t(70015)
        services = uint64_t(0)
        timestamp = int64_t(time.time())

        addr_recv_services = uint64_t(0)
        addr_recv_ip = ipv6_from_ipv4(PEER_HOST)
        addr_recv_port = uint16_t(PEER_PORT)

        addr_trans_services = uint64_t(0)
        addr_trans_ip = ipv6_from_ipv4(self.listener_address[0])
        addr_trans_port = uint16_t(self.listener_address[1])

        nonce = uint64_t(0)

        user_agent_bytes = compactsize_t(0)

        starting_height = int32_t(0)  # highest current block: 656954

        relay = bool_t(False)

        payload = version + services + timestamp + addr_recv_services \
                  + addr_recv_ip + addr_recv_port + addr_trans_services \
                  + addr_trans_ip + addr_trans_port + nonce + \
                  user_agent_bytes + starting_height + relay

        return payload


if __name__ == '__main__':
    lab5 = Lab5()
    lab5.run()
