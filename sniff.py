from scapy.all import sniff
from scapy.all import get_if_list
from collections import defaultdict
from threading import Thread
from queue import Queue
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