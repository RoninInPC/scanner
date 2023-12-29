import sys
from datetime import datetime

from ParserArgument import ParserArgument
from PortsScanner import PortsScanner

from netaddr import IPRange

def portRangeList(a, z):
    return [c for c in range(a, z + 1)]


def ipRangeList(a, z):
    return IPRange(a, z)

if __name__ == '__main__':
    print("Start Time ", datetime.now())

    parserArgument = ParserArgument()
    parser = parserArgument.getParser()

    args = parser.parse_args(sys.argv[1:])

    ip_range = None;
    port_list = [];
    if args.ip:
        ip_range = ipRangeList(args.ip[0], args.ip[0])
    if args.net:
        ip_range = ipRangeList(args.net[0], args.net[1])
    if args.port:
        port_list = args.port;
    if args.port_range:
        port_list = portRangeList(args.port_range[0], args.port_range[1])

    scan = PortsScanner(ip_range, port_list  = port_list, typesc=args.scanner, tm=args.timeout, w=args.wait, threads=args.th)

    print(scan.scanChoise())

    print("End Time ", datetime.now())