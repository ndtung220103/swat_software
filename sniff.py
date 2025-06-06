from scapy.all import sniff
from scapy.all import get_if_list
from scapy.all import Ether, IP, TCP, UDP, Raw
from collections import defaultdict
from threading import Thread
from queue import Queue
import datetime
import time
import threading


PACKETS = Queue()


def is_if_up(ifname):
    try:
        result = subprocess.check_output(f"cat /sys/class/net/{ifname}/operstate",
            shell=True)
        return result.strip() ==b"up"
    except:
        return False
    
def packet_callback(packet):
    PACKETS.put(packet)

def start_sniff():
    interface = [
        iface for iface in get_if_list()
        if (iface.startswith("s1-") or iface.startswith("s2-")) and is_if_up(iface)
    ]
    print(interface)
    t = Thread(target=sniff, kwargs={'iface': interface, 'prn': packet_callback, 'store': 0})
    t.daemon = True
    t.start()
    #sniff(iface="s1-eth2", prn=packet_callback, store =0)

def detect():
    now = time.time()
    while True:
        packet = PACKETS.get()
        print(packet.summary())
        timestamp = datetime.datetime.fromtimestamp(packet.time).isoformat()
        # Ethernet layer
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
        else:
            src_mac = dst_mac = None
        
        # IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = dst_ip = None

        # Transport layer
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            src_port = dst_port = None
        
        print(f"Timestamp: {timestamp}")
        print(f"MAC: {src_mac} -> {dst_mac}")
        print(f"IP: {src_ip} -> {dst_ip}")
        print(f"Port: {src_port} -> {dst_port}")

def monitor():
    detect()
    while True:
        # In thông tin ra màn hình hoặc gửi thông báo
        print('')
        time.sleep(5)

if __name__ == '__main__':
    print("Khởi động bắt gói tin...")
    start_sniff()
    threading.Thread(target=monitor, daemon=True).start()
    while True:
        time.sleep(1)