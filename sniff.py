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
KEYMATCH = Queue()

syn_packets = defaultdict(list)
synack_packets = defaultdict(list)

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
    while True:
        packet = PACKETS.get()
        if packet.haslayer(TCP) and packet.haslayer(IP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags
            timestamp = datetime.datetime.fromtimestamp(packet.time)

            # Định danh kết nối
            conn_key = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
            reverse_key = f"{ip_layer.dst}:{tcp_layer.dport} -> {ip_layer.src}:{tcp_layer.sport}"

            if flags == 'S':
                if conn_key not in syn_packets:
                    syn_packets[conn_key] = []
                    KEYMATCH.put(conn_key)
                syn_packets[conn_key].append(timestamp)

            elif flags == 'SA':
                if reverse_key not in synack_packets:
                    synack_packets[reverse_key] = []
                synack_packets[reverse_key].append(timestamp)

def monitor():
    time.sleep(1)
    while True:
        if KEYMATCH.qsize() > 2:
            conn_key = KEYMATCH.get()
            if conn_key in syn_packets and conn_key in synack_packets:
                syn_times = syn_packets[conn_key]
                synack_times = synack_packets[conn_key]

                syn_earliest = min(syn_times)
                synack_latest = max(synack_times)
                syn_latest = max(syn_times)
                synack_earliest = min(synack_times)

                RTT = (synack_latest - syn_earliest)
                Latency = (syn_latest-syn_earliest)

                print(f" Kết nối: {conn_key}")
                print(f"→ Số lần xuất hiện SYN: {len(syn_times)}")
                print(f"→ Thời gian SYN sớm nhất: {syn_earliest.isoformat(timespec='microseconds')}")
                print(f"→ Thời gian SYN-ACK muộn nhất: {synack_latest.isoformat(timespec='microseconds')}")
                print(f"→ Trễ truyền dẫn: {Latency} ms")
                print(f"→ Hiệu thời gian: {RTT} ms")

                del syn_packets[conn_key]
                del synack_packets[conn_key]

if __name__ == '__main__':
    print("Khởi động bắt gói tin...")
    start_sniff()
    threading.Thread(target=detect, daemon=True).start()
    threading.Thread(target=monitor, daemon=True).start()
    while True:
        time.sleep(1)