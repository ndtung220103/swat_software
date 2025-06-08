from scapy.all import sniff
from scapy.all import get_if_list
from scapy.all import Ether, IP, TCP, UDP, Raw
from collections import defaultdict
from threading import Thread
from queue import Queue
import datetime
import time
import requests
import json
import threading


PACKETS = Queue()
KEYMATCH = Queue()

request_packets = defaultdict(list)
response_packets = defaultdict(list)
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
        if packet.haslayer(TCP) and packet.haslayer(IP) and Raw in packet:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            print(packet.summary())
            payloadhex = bytes (packet [Raw]).hex()
            print("Payload hex: ", payloadhex)
            payload = bytes (packet [Raw]) 
            print("Payload bytes: ", payload)
            # bắt gói tin gửi yêu cầu đọc và gửi dữ liệu
            if payload[0] == 0x6f:  
                timestamp = datetime.datetime.fromtimestamp(packet.time)
                # Định danh kết nối
                conn_key = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
                reverse_key = f"{ip_layer.dst}:{tcp_layer.dport} -> {ip_layer.src}:{tcp_layer.sport}"

                if tcp_layer.dport == 44818:
                    try:
                        tag_start = payload.find(b'LIT')
                        if tag_start != -1:
                            tag_end = payload.find(b'\x00', tag_start)
                            tag = payload[tag_start:tag_end].decode('ascii')
                            print("Tag yêu cầu đọc:", tag)
                    except Exception as e:
                        print("Không thể trích xuất tag:", e)

                    if conn_key not in request_packets:
                        request_packets[conn_key] = []
                        KEYMATCH.put(conn_key)
                    request_packets[conn_key].append(timestamp)

                elif tcp_layer.sport == 44818:
                    try:
                        data_payload = payload[44:]  # điều chỉnh offset nếu cần
                        print("Dữ liệu trả về (hex):", data_payload.hex())
                    except Exception as e:
                        print("Không thể trích xuất dữ liệu:", e)
                        
                    if reverse_key not in response_packets:
                        response_packets[reverse_key] = []
                    response_packets[reverse_key].append(timestamp)

            # ip_layer = packet[IP]
            # tcp_layer = packet[TCP]
            # flags = tcp_layer.flags
            # timestamp = datetime.datetime.fromtimestamp(packet.time)

            # # Định danh kết nối
            # conn_key = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}"
            # reverse_key = f"{ip_layer.dst}:{tcp_layer.dport} -> {ip_layer.src}:{tcp_layer.sport}"

            # if flags == 'S':
            #     if conn_key not in request_packets:
            #         request_packets[conn_key] = []
            #         KEYMATCH.put(conn_key)
            #     request_packets[conn_key].append(timestamp)

            # elif flags == 'SA':
            #     if reverse_key not in response_packets:
            #         response_packets[reverse_key] = []
            #     response_packets[reverse_key].append(timestamp)

def monitor():
    time.sleep(3)
    while True:
        if KEYMATCH.qsize() > 20:
            conn_key = KEYMATCH.get()
            if conn_key in request_packets and conn_key in response_packets:
                request_times = request_packets[conn_key]
                response_times = response_packets[conn_key]

                request_earliest = min(request_times)
                response_latest = max(response_times)
                request_latest = max(request_times)
                response_earliest = min(response_times)

                RTT = (response_latest -request_earliest).total_seconds()
                Latency = (request_latest -request_earliest).total_seconds()
                NUM = len(request_times)

                src_part, dst_part = conn_key.split(" -> ")
                src_ip, src_port = src_part.split(":")
                dst_ip, dst_port = dst_part.split(":")

                key = f"{src_ip} -> {dst_ip}"
                metrics = {
                    "Latency": Latency,
                    "RTT": RTT,
                    "NUM": NUM
                }
                if key not in list_metric:
                    list_metric[key] = metrics
                else:
                    list_metric[key]["RTT"] = alpha * RTT + (1 - alpha) * list_metric[key]["RTT"]
                    list_metric[key]["Latency"] = alpha * Latency + (1 - alpha) * list_metric[key]["Latency"]
                    list_metric[key]["NUM"] = NUM
                del request_packets[conn_key]
                del response_packets[conn_key]

def send_to_dashboard():
    while True:
        try:
            response = requests.post(
                "http://localhost:5000/metrics",  # Địa chỉ Flask server
                json=list_metric
            )
        except Exception as e:
            print("Error sending to dashboard:", e)
        time.sleep(0.5)

if __name__ == '__main__':
    print("Khởi động bắt gói tin...")
    start_sniff()
    threading.Thread(target=detect, daemon=True).start()
    threading.Thread(target=monitor, daemon=True).start()
    threading.Thread(target=send_to_dashboard, daemon=True).start()
    while True:
        time.sleep(1)