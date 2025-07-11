from scapy.all import sniff
from scapy.all import get_if_list
from scapy.all import Ether, IP, TCP, UDP, Raw
from collections import defaultdict
from threading import Thread
from queue import Queue
import datetime
import time
import re
import requests
import json
import threading


PACKETS = Queue()
KEYMATCH = Queue()
SENSORKEY = Queue()

request_packets = defaultdict(list)
ack_packets = defaultdict(list)
response_packets = defaultdict(list)
list_metric = {}
key_to_tag = {}
key_to_value = {}
sensors_value ={}
mess ={}
alpha = 0.05
queue_num = 20
MAX_TIME = 999999999
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
        if packet.haslayer(TCP) and packet.haslayer(IP) :
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            conn_key = f"{ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}{tcp_layer.ack}"
            reverse_key = f"{ip_layer.dst}:{tcp_layer.dport} -> {ip_layer.src}:{tcp_layer.sport}{tcp_layer.seq}"
            timestamp = float(packet.time)
            if tcp_layer.flags == 'A':
                if reverse_key in request_packets:
                    if reverse_key not in ack_packets:
                        ack_packets[reverse_key] =[]
                    ack_packets[reverse_key].append(timestamp)
            if Raw in packet:
                payload = bytes (packet [Raw]) 

                # bắt gói tin gửi yêu cầu đọc và gửi dữ liệu
                if payload[0] == 0x6f: 
                    tag ='' 
                    if tcp_layer.dport == 44818:
                        # print(payload.hex())
                        # id = payload[12:20] #Sender Context
                        # print(id)
                        #print(packet.summary())
                        #print("time: ",timestamp)
                        try:
                            payload_str = payload.decode('ascii', errors='ignore')
                            tag_start_send = payload.find(b'\xc3')
                            tags = re.findall(r'\b(?:LIT|MV|P|FIT|AIT|DPIT)\d{3}(?::\d)?\b', payload_str)
                            for tag in tags:
                                if conn_key not in request_packets:
                                    SENSORKEY.put(conn_key)
                                key_to_tag[conn_key] = str(tag)
                            # nếu là lệnh send thì dữ liệu ngay trong yêu cầu
                            if tag_start_send != -1 and tag_start_send >59 and tag_start_send < 70:
                                value = struct.unpack('<h', payload[tag_start_send+4:tag_start_send+6])[0]
                                if conn_key in key_to_value:
                                    if value != key_to_value[conn_key]:
                                        msg = "Phát hiện thay đổi dữ liệu %s từ %s thành %s on key %s"%(key_to_tag[conn_key],key_to_value[conn_key],value, conn_key)
                                        mess["mess3"] = msg
                                    else:
                                        mess.clear()
                                key_to_value[conn_key] = value

                        except Exception as e:
                            print("Không thể trích xuất tag:", e)
                        if conn_key not in request_packets:
                            request_packets[conn_key] = []
                            KEYMATCH.put(conn_key)
                        request_packets[conn_key].append(timestamp)

                    elif tcp_layer.sport == 44818:
                        try:
                            marker = payload[44:46]
                            if marker == b'\xca\x00' and len(payload) >= 50:
                                # Số thực float32
                                value = struct.unpack('<f', payload[46:50])[0] 
                                if reverse_key in key_to_tag:
                                    if reverse_key in key_to_value:
                                        if value != key_to_value[reverse_key]:
                                            msg = "Phát hiện thay đổi dữ liệu %s từ %s thành %s on key %s"%(key_to_tag[reverse_key],key_to_value[reverse_key],value,reverse_key)
                                            mess["mess3"] = msg
                                        else:
                                            mess.clear()
                                    key_to_value[reverse_key] = value

                            elif marker == b'\xc3\x00':
                                # Số nguyên int32
                                value = struct.unpack('<h', payload[46:48])[0]  
                                if reverse_key in key_to_tag:
                                    if reverse_key in key_to_value:
                                        if value != key_to_value[reverse_key]:
                                            msg = "Phát hiện thay đổi dữ liệu %s từ %s thành %s on key %s"%(key_to_tag[reverse_key],key_to_value[reverse_key],value, reverse_key)
                                            mess["mess3"] = msg
                                        else:
                                            mess.clear()
                                    key_to_value[reverse_key] = value

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
    global queue_num
    while True:
        if KEYMATCH.qsize() > queue_num:
            conn_key = KEYMATCH.get()
            src_part, dst_part = conn_key.split(" -> ")
            src_ip, src_port = src_part.split(":")
            dst_ip, dst_port = dst_part.split(":")

            key = f"{src_ip} -> {dst_ip}"

            if conn_key in request_packets:
                request_times = request_packets[conn_key]
                NUM = len(request_times)
                if conn_key in ack_packets:
                    #response_times = response_packets[conn_key]
                    response_times = ack_packets[conn_key]

                    request_earliest = min(request_times)
                    response_latest = max(response_times)
                    request_latest = max(request_times)
                    response_earliest = min(response_times)

                    RTT = response_latest -request_earliest
                    Latency = request_latest -request_earliest

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

                    queue_num = max(20, len(list_metric)*3)
                    del request_packets[conn_key]
                    del response_packets[conn_key]
                    del ack_packets[conn_key]
                else:
                    metrics = {
                        "Latency": MAX_TIME,
                        "RTT": MAX_TIME,
                        "NUM": NUM
                    }
                    list_metric[key] = metrics
                    del request_packets[conn_key]

def recive_values():
    time.sleep(0.5)
    while True:
        if SENSORKEY.qsize() > 2:
            conn_key = SENSORKEY.get()
            if conn_key in key_to_tag and conn_key in key_to_value:
                tag = key_to_tag[conn_key]
                value = key_to_value[conn_key]
                sensors_value[tag] = value
                del key_to_tag[conn_key]
                del key_to_value[conn_key]
            if conn_key in key_to_tag and conn_key not in key_to_value:
                del key_to_tag[conn_key]
            if conn_key not in key_to_tag and conn_key in key_to_value:
                del key_to_value[conn_key]

def send_to_dashboard():
    while True:
        try:
            requests.post(
                "http://localhost:5000/metrics", 
                json=list_metric
            )
        except Exception as e:
            print("Error sending to dashboard:", e)

        try:
            requests.post(
                "http://localhost:5000/sensors",  
                json=sensors_value
            )
        except Exception as e:
            print("Error sending to dashboard:", e)

        try:
            requests.post(
                "http://localhost:5000/mess",  
                json=mess
            )
        except Exception as e:
            print("Error sending to dashboard:", e)
        time.sleep(0.5)

if __name__ == '__main__':
    print("Khởi động bắt gói tin...")
    start_sniff()
    threading.Thread(target=detect, daemon=True).start()
    threading.Thread(target=monitor, daemon=True).start()
    threading.Thread(target=recive_values, daemon=True).start()
    threading.Thread(target=send_to_dashboard, daemon=True).start()

    while True:
        time.sleep(1)