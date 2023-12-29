import socket
from concurrent.futures import ThreadPoolExecutor, as_completed, wait

import requests
from scapy.layers.inet import IP, TCP, sr1
import time

import socks


def vulnEasyChatCerverCheck(ip, port):
    try:
        response = requests.get(f'http://{ip}:{port}', timeout=10)
        print(response.headers)
        if 'Easy Chat Server' in response.headers.get('Server'):
            print(f"{ip}:{port}  have vuln Easy Chat Server")
    except errno:
        print(errno)
        return


class PortsScanner:
    def __init__(self, ip_list, port_list=None, typesc="fsyn", threads=1, tm=5, w=0):
        self.ip_list = ip_list
        self.port_list = port_list
        self.typesc = typesc
        self.threads = threads
        self.tm = tm
        self.w = w

    def torScanPort(self, ip, port):

        syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        time.sleep(self.w)
        print(ip," ",port)
        resp_packet = sr1(syn_packet, timeout=1, verbose=False)

        if resp_packet is not None:
            if resp_packet.haslayer(TCP):
                if resp_packet.getlayer(TCP).flags == 0x12:
                    print(f"{ip}:{port} is open/{resp_packet.sprintf('%TCP.sport%')}")
                    vulnEasyChatCerverCheck(ip, port)
                    return ip, port
                print(f"{ip}:{port} is close/{resp_packet.sprintf('%TCP.dport%')}")
        return

    def synScanPort(self, ip, port):
        syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
        time.sleep(self.w)
        resp_packet = sr1(syn_packet, timeout=self.tm, verbose=False)

        if resp_packet is None:
            return

        if resp_packet.haslayer(TCP):
            if resp_packet.getlayer(TCP).flags == 0x12:
                print(f"{ip}:{port} is open/{resp_packet.sprintf('%TCP.sport%')}")
                return ip, port
        print(f"{ip}:{port} is close/{resp_packet.sprintf('%TCP.dport%')}")
        return

    def finScanPort(self, ip, port):
        fin_packet = IP(dst=ip) / TCP(dport=port, flags="F")
        time.sleep(self.w)

        resp_packet = sr1(fin_packet, timeout=self.tm, verbose=False)

        if resp_packet is None:
            return

        if resp_packet.haslayer(TCP):
            if resp_packet.getlayer(TCP).flags == 0x14:
                print(f"{ip}:{port} is open/{fin_packet.sprintf('%TCP.sport%')}")
                return ip, port
        print(f"{ip}:{port} is close/{fin_packet.sprintf('%TCP.dport%')}")
        return

    def scan(self, mode, method):
        result = {}
        with ThreadPoolExecutor(max_workers=mode) as executor:
            futures = [executor.submit(method, str(ip), port) for ip in self.ip_list for port in self.port_list]

        for future in as_completed(futures):
            res = future.result()
            if res is not None:
                (ip, port) = res
                if ip not in result:
                    result[ip] = list()
                result[ip].append(port)
        wait(futures)
        return result

    def scanChoise(self):
        if self.port_list:
            dictionary = dict([("syn", self.synScanPort),
                               ("fin", self.finScanPort),
                               ("cnt", self.torScanPort)])
            if self.typesc == "cnt":
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
                socket.socket = socks.socksocket
            if self.typesc:
                return self.scan(self.threads, dictionary[self.typesc])
            return
