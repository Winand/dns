# -*- coding: utf-8 -*-
# http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
# http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
# http://ru.wikipedia.org/wiki/Ресурсные_записи_DNS
# http://tools.ietf.org/html/rfc1035

import socket
# import sys
import timeit
from random import randrange
from struct import pack, unpack
from io import BytesIO
import binascii

PORT_DNS = 53
QTYPES = {"A": 0x0001, "NS": 0x0002, "CNAME": 0x0005, "SOA": 0x0006,
          "PTR": 0x000c, "MX": 0x000f, "AAAA": 0x001c}
QTYPESR = dict(zip(QTYPES.values(), QTYPES.keys()))  # key->val swapped
QCLASSES = {"IN": 0x0001}
QCLASSESR = dict(zip(QCLASSES.values(), QCLASSES.keys()))

# DNS Packet Structure
# +---------------------+
# | Header              |
# +---------------------+
# | Question            | the question for the name server
# +---------------------+
# | Answer              | Answers to the question
# +---------------------+
# | Authority           | Authority resource records
# +---------------------+
# | Additional          | Additional resource records
# +---------------------+


def to_hex(s):
    if isinstance(s, str):
        s = s.encode()
    return binascii.hexlify(s).decode()


def buildHeaderFlagField(QR, OPCODE, AA, TC, RD, RA, Z, RCODE):
    QR, OPCODE, AA, TC, RD, RA, Z, RCODE = \
    int(QR), int(OPCODE), int(AA), int(TC), int(RD), int(RA), int(Z), int(RCODE)
    #   F  E  D  C  B  A  9  8| 7  6  5  4  3  2  1  0 (bytes are swapped on pack(...))
    # |QR|  Opcode  |AA|TC|RD|RA|   Z    |   RCODE    |
    return (QR<<15) + (OPCODE<<11) + (AA<<10) + (TC<<9) + (RD<<8) + \
          (RA<<7) + (Z<<4) + RCODE


def parseHeaderFlagField(flags):
    QR = str(flags >> 15)
    OPCODE = str(flags >> 11 & 0b1111).rjust(4, '0')
    AA = str(flags >> 10 & 1)
    TC = str(flags >> 9 & 1)
    RD = str(flags >> 8 & 1)
    RA = str(flags >> 7 & 1)
    Z = str(flags >> 4 & 0b111).rjust(3, '0')
    RCODE = str(flags & 0b1111).rjust(4, '0')
    return QR, OPCODE, AA, TC, RD, RA, Z, RCODE


def splitDomainName(domain_name):
    "split into parts: www.ya.ru = 3, www, 2, ya, 2, ru, 0"
    domain_parts = domain_name.split(".")
    return [f(part) for part in domain_parts
            for f in (lambda x: chr(len(x)), str)] + ['\0']


def reprHexData(data):
    "convert bytes (string) into sequence of hex-groups: 0001 78fa ..."
    h = binascii.hexlify(data).decode()
    return " ".join([h[i:i+4] for i in range(0, len(h), 4)])


def reprIPv6addr(addrb):
    "convert binary (string) representation of IPv6 into readable format"
    groups = [i.lstrip("0") for i in reprHexData(addrb).split(" ")]
    empties, start = [], -1
    for i, v in enumerate(groups):
        if not v:
            if start == -1:
                start = i
        elif start != -1:  # end of empty sequence
            empties.append((start, i-start))
            start = -1
    if empties:  # reduce: delete longest zero sequence
        longest, ii = (-1, -1), -1
        for i, v in enumerate(empties):
            if v[1] > longest[1]:
                longest, ii = v, i
        del empties[ii]
        for i in empties:
            for j in range(i[1]):
                groups[i[0]+j] = "0"
        for i in range(longest[1]-1):
            del groups[longest[0]]
        if longest[0] == 0:  # if :: is at the beginning
            groups[longest[0]] = ":"
    return ":".join(groups)


def buildQuestion(domain_name, qtype="A", qclass="IN"):
    #   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                      ID                       |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |QR| Opcode |AA|TC|RD|RA|   Z    |    RCODE     |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    QDCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ANCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    NSCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    # |                    ARCOUNT                    |
    # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ID = randrange(0xffff)  # Randomly chosen ID
    QR,  OPCODE, AA,  TC,  RD,   RA,  Z,     RCODE = \
    '0', '0000', '0', '0', '1',  '0', '000', '0000'
    Flags = buildHeaderFlagField(QR, OPCODE, AA, TC, RD, RA, Z, RCODE)
    QDCOUNT = 0x0001  # One question follows
    ANCOUNT = 0x0000  # No answers follow
    NSCOUNT = 0x0000  # No records follow
    ARCOUNT = 0x0000  # No additional records follow
    header = pack("!HHHHHH", ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

#   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QNAME                     |
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QTYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QCLASS                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    domain_name = domain_name.encode('idna').decode().strip(".")  # remove incorrect edge dots
    qnamep = splitDomainName(domain_name)
    QNAME = "".join(qnamep).encode()
    QTYPE = QTYPES[qtype]
    QCLASS = QCLASSES[qclass]

    print("----Header----")
    print("|ID: 0x%04x" % ID)
    print("|Flags: 0x%04x" % Flags, "(QR="+QR, "OPCODE="+OPCODE, "AA="+AA,
          "TC="+TC, "RD="+RD, "RA="+RA, "Z="+Z, "RCODE="+RCODE+")")
    print("|QDCOUNT: 0x{0:04x} ({0:d} question)".format(QDCOUNT))
    print("|ANCOUNT: 0x{0:04x} ({0:d} answer(s))".format(ANCOUNT))
    print("|NSCOUNT: 0x{0:04x} ({0:d} authority(s))".format(NSCOUNT))
    print("|ARCOUNT: 0x{0:04x} ({0:d} additional(s))".format(ARCOUNT))
    print("--------------")
    print("---Question---")
    print("|QNAME:", " ".join([to_hex(i) for i in qnamep]),
          "(%s)" % alterIdna(domain_name))
    print("|QTYPE: 0x%04x" % QTYPE, "(%s)" % qtype)
    print("|QCLASS: 0x%04x" % QCLASS, "(%s)" % qclass)
    print("--------------")
    return header + QNAME + pack("!HH", QTYPE, QCLASS)


def readDNSstr(dat):
    "reads string from answer, returns (readable_format, bytes_in_hex_format)"
    # FIXME: infinite loop may occur
    parts = []
    realparts = []
    pl = ord(dat.read(1))
    while pl:
        if pl >= 0b11000000:  # pointer
            # 0123456789abcdef
            # 11...offset.....
            dat.seek(dat.tell()-1)  # rewind 1 byte back
            pointer = dat.read(2)
            realparts.append(to_hex(pointer))
            offset = unpack("!H", pointer)[0] & 0x3fff
            fp = dat.tell()
            dat.seek(offset)
            parts.append(readDNSstr(dat)[0])  # recursive
            dat.seek(fp)
            break
        else:
            s = dat.read(pl)
            realparts += [to_hex(chr(pl)), to_hex(s)]
            parts.append(s.decode())
        pl = ord(dat.read(1))
    if not pl:
        realparts.append('00')
    return ".".join(parts), realparts


def parseAnswerRecord(dat):
    "parse answer, authority, additional sections of answer"
    domain_name, namep = readDNSstr(dat)
    TYPE, CLASS, TTL, RDLENGTH = unpack('!HHLH', dat.read(10))
    stype = QTYPESR[TYPE]
    rdatap = dat.tell()
    RDATA = dat.read(RDLENGTH)
    dat.seek(rdatap)  # rewind to start of RDATA

    print("|NAME: %s (%s)" % (" ".join(namep), alterIdna(domain_name)))
    print("|TYPE: 0x%04x" % TYPE, "(%s)" % stype)
    print("|CLASS: 0x%04x" % CLASS, "(%s)" % QCLASSESR[CLASS])
    print("|TTL: 0x{0:08x} ({0:d} sec)".format(TTL))
    print("|RDLENGTH: 0x{0:04x} ({0:d} byte(s))".format(RDLENGTH))
    print("|RDATA:", reprHexData(RDATA), end=' ')
    if stype == "A":
        RDATA, = unpack('!4s', dat.read(4))
        print("(IP %s)" % ".".join([str(b) for b in RDATA]))
    elif stype == "PTR":
        PTRDName = readDNSstr(dat)[0]
        print("(PTRDName=%s)" % PTRDName)
    elif stype == "SOA":  # Start Of Authority Resource Record (Type Value 6)
        MName = readDNSstr(dat)[0]
        RName = readDNSstr(dat)[0]
        Serial, Refresh, Retry, Expire, Minimum = unpack('!LLLLL',
                                                         dat.read(20))
        print("(MName=%s, RName=%s, Serial=0x%08x, Refresh=%ds, Retry=%ds, "
              "Expire=%ds, Minimum=%ds)" % (MName, RName.replace(".", "@", 1),
                                            Serial, Refresh, Retry, Expire,
                                            Minimum))
    elif stype == "CNAME":
        CName = readDNSstr(dat)[0]
        print("(CName=%s)" % CName)
    elif stype == "NS":
        NSDName = readDNSstr(dat)[0]
        print("(NSDName=%s)" % NSDName)
    elif stype == "MX":
        Preference, = unpack('!H', dat.read(2))
        Exchange = readDNSstr(dat)[0]
        print("(Preference=%d, Exchange=%s)" % (Preference, Exchange))
    elif stype == "AAAA":
        RDATA, = unpack('!16s', dat.read(16))
        print("(IPv6 %s)" % reprIPv6addr(RDATA))
    else:
        dat.read(RDLENGTH)  # skip rdata field
        print()
    print("--------------")


def alterIdna(s):
    "decodes idna, returns 'idnastr / str' or 'idnastr' if 'str' is the same"
    s2 = s.encode().decode('idna')  # .encode(sys.stdout.encoding or "cp1251", 'ignore')
    return s if s == s2 else " / ".join([s, s2])


def parseAnswer(data):
    dat = BytesIO(data)
    ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = \
        unpack('!HHHHHH', dat.read(12))
    QR, OPCODE, AA, TC, RD, RA, Z, RCODE = parseHeaderFlagField(Flags)
    domain_name, qnamep = readDNSstr(dat)
    QTYPE, QCLASS = unpack('!HH', dat.read(4))

    print("----Header----")
    print("|ID: 0x%04x" % ID)
    print("|Flags: 0x%04x" % Flags, "(QR="+QR, "OPCODE="+OPCODE, "AA="+AA,
          "TC="+TC, "RD="+RD, "RA="+RA, "Z="+Z, "RCODE="+RCODE+")")
    print("|QDCOUNT: 0x{0:04x} ({0:d} question)".format(QDCOUNT))
    print("|ANCOUNT: 0x{0:04x} ({0:d} answer(s))".format(ANCOUNT))
    print("|NSCOUNT: 0x{0:04x} ({0:d} authority(s))".format(NSCOUNT))
    print("|ARCOUNT: 0x{0:04x} ({0:d} additional(s))".format(ARCOUNT))
    print("--------------")
    print("---Question---")
    print("|QNAME: %s (%s)" % (" ".join(qnamep), alterIdna(domain_name)))
    print("|QTYPE: 0x%04x" % QTYPE, "(%s)" % QTYPESR[QTYPE])
    print("|QCLASS: 0x%04x" % QCLASS, "(%s)" % QCLASSESR[QCLASS])
    print("--------------")

    for i in range(ANCOUNT):
        print("---ANSWER %d---" % (i+1))
        parseAnswerRecord(dat)
    for i in range(NSCOUNT):
        print("---AUTHORITY %d---" % (i+1))
        parseAnswerRecord(dat)
    for i in range(ARCOUNT):
        print("---ADDITIONAL %d---" % (i+1))
        parseAnswerRecord(dat)


def isIPv4(s):
    "checks if string is ipv4 address, returns address splitted into parts"
    parts = s.split(".")
    if len(parts) == 4:
        parts_chk = list(map(lambda x: x
                             if x.isdigit() and 0 <= int(x) <= 255
                             else None, parts))
        if None not in parts_chk:
            return parts_chk


print("====== WINAND DNS QUERY PROGRAM ======")
print()
while True:
    DOMAIN = input("Input domain name [www.google.com] or IPv4: ") or \
        'www.google.com'
    parts = isIPv4(DOMAIN)
    if parts:
        DOMAIN = ".".join(parts[::-1]) + ".in-addr.arpa"
        TYPE = "PTR"
        print("Reverse DNS lookup will be performed with PTR query. "
              "PRESS ENTER TO CONTINUE", end=' ')
        input()
    else:
#        DOMAIN = DOMAIN.decode(sys.stdin.encoding or "cp1251", 'ignore')
        TYPE = input("Input query type (%s) [A]: " %
                     ", ".join(QTYPES.keys())).upper() or 'A'
        if TYPE not in QTYPES:
            print("Unknown query type, assume A. PRESS ENTER TO CONTINUE",
                  end=' ')
            input()
            TYPE = "A"
    ADDR_DNS = input("Input DNS server IP address [8.8.8.8]: ") or '8.8.8.8'
    if not isIPv4(ADDR_DNS):
        print("Entered string is not an IPv4 address, assume 8.8.8.8. "
              "PRESS ENTER TO CONTINUE", end=' ')
        input()
        ADDR_DNS = "8.8.8.8"

    print()
    print("=== REQUEST ===")
    q = buildQuestion(DOMAIN, TYPE)
    print("== REQUEST DATA ==")
    print(reprHexData(q))
    print()
    print("Sending request to %s ..." % ":".join((ADDR_DNS, str(PORT_DNS))))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        time_a = timeit.default_timer()
        sent = sock.sendto(q, (ADDR_DNS, PORT_DNS))
        data, server = sock.recvfrom(16384)  # 16KB
        # data = "648581800001000100000000037777770c6e6f7274686561737465726e036564750000010001c00c000100010000017000049b211144".decode('hex')
        print("Request finished in %.4f sec" % (timeit.default_timer() -
                                                time_a))
    finally:
        sock.close()
    print()
    print("=== ANSWER ===")
    parseAnswer(data)
    print("== ANSWER DATA ==")
    print(reprHexData(data))
    print()
    if input("Enter 'q' to exit program or hit Enter to try again: "
             ).lower() == 'q':
        break
    print()
