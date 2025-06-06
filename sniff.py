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
list_metric = {}
alpha = 0.2
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
        if KEYMATCH.qsize() > 5:
            conn_key = KEYMATCH.get()
            if conn_key in syn_packets and conn_key in synack_packets:
                syn_times = syn_packets[conn_key]
                synack_times = synack_packets[conn_key]

                syn_earliest = min(syn_times)
                synack_latest = max(synack_times)
                syn_latest = max(syn_times)
                synack_earliest = min(synack_times)

                RTT = float(synack_latest - syn_earliest)
                Latency = float(syn_latest-syn_earliest)
                NO = len(syn_times)
                src_part, dst_part = conn_key.split(" -> ")
                src_ip, src_port = src_part.split(":")
                dst_ip, dst_port = dst_part.split(":")

                key = f"{src_ip} -> {dst_ip}"
                metrics = {
                    "Latency": Latency,
                    "RTT": RTT,
                    "NO": NO
                }
                if key not in list_metric:
                    list_metric[key]= metrics
                else:
                    list_metric[key].RTT = alpha*RTT + (1-alpha)*list_metric[key].RTT
                    list_metric[key].Latency = alpha*Latency + (1-alpha)*list_metric[key].Latency
                    list_metric[key].NO = NO

                del syn_packets[conn_key]
                del synack_packets[conn_key]

def send_to_dashboard():
    while True:
        print(list_metric)
        time.sleep(3)

if __name__ == '__main__':
    print("Khởi động bắt gói tin...")
    start_sniff()
    threading.Thread(target=detect, daemon=True).start()
    threading.Thread(target=monitor, daemon=True).start()
    threading.Thread(target=send_to_dashboard, daemon=True).start()
    while True:
        time.sleep(1)