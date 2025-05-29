from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import threading
import socket
import json
import time
import requests

log = core.getLogger()

# Danh sách ánh xạ IP-to-MAC hợp lệ
VALID_IP_TO_MAC = {
    '192.168.1.10': '00:1D:9C:C7:B0:70',
    '192.168.1.20': '00:1D:9C:C8:BC:46',
    '192.168.1.30': '00:1D:9C:C8:BD:F2',
    '192.168.1.40': '00:1D:9C:C7:FA:2C',
    '192.168.1.50': '00:1D:9C:C8:BC:2F',
    '192.168.1.60': '00:1D:9C:C7:FA:2D',
    '192.168.1.70': '00:1D:9C:C8:BC:70'
}

cip_latency_tracker = {}
bandwidth_tracker = {}
sensor_data = {}
latency_list = {}
bandwidth_list = {}
ema_latency = {}  # Exponential Moving Average - EMA
ema_bandwidth = {}  
alpha = 0.3

def send_metrics_to_dashboard(metrics):
    try:
        url = "http://127.0.0.1:5000/metrics"
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=metrics)
        if response.status_code == 200:
            log.info("[DASHBOARD] Sent metrics successfully")
        else:
            log.warning(f"[DASHBOARD] Failed to send metrics: {response.status_code}")
    except Exception as e:
        log.error(f"[DASHBOARD] Exception: {e}")

# def send_mess_to_dashboard(mess):
#     try:
#         url = "http://127.0.0.1:5000/mess"
#         headers = {'Content-Type': 'application/json'}
#         response = requests.post(url, headers=headers, json=mess)
#         if response.status_code == 200:
#             log.info("[DASHBOARD] Sent metrics successfully")
#         else:
#             log.warning(f"[DASHBOARD] Failed to send metrics: {response.status_code}")
#     except Exception as e:
#         log.error(f"[DASHBOARD] Exception: {e}")

def start_udp_server():
    global sensor_data
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 9999))
    log.info("[HMI-UDP] Listening for UDP sensor data on port 9999")

    while True:
        try:
            data, addr = sock.recvfrom(8192)
            decoded = data.decode()
            sensor_data = json.loads(decoded)
            log.info(f"[HMI-UDP] From {addr}: {sensor_data}")
        except Exception as e:
            log.error(f"[HMI-UDP] Error: {e}")

class AntiARPCachePoisoning (object):
    def __init__(self, connection):
        self.connection = connection
        self.macToPort = {}
        connection.addListeners(self)
        log.info(f"Switch {connection.dpid} is now monitored.")

    def _handle_PacketIn(self, event):
        """
        Khi switch nhận gói tin không có rule, nó gửi PacketIn lên controller.
        Ở đây, ta sẽ in thông tin gói tin và gửi PacketOut để tiếp tục chuyển tiếp gói tin.
        """
        
        packet = event.parsed
        

        log.info("Received Packet: %s", packet)
        if not packet.parsed:
            log.warning("Received incomplete packet, ignoring.")
            return
        
        self.macToPort[packet.src] = event.port

        def drop():
            if event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)
            else:
                msg = of.ofp_packet_out()
                msg.data = event.ofp  
                msg.in_port = event.port
                self.connection.send(msg)
        
        def flood(message=None):
            msg = of.ofp_packet_out()
            if message is not None:
                log.debug(message)
            log.debug("%i: flood %s -> %s" % (event.dpid, packet.src, packet.dst))

            action = of.ofp_action_output(port=of.OFPP_FLOOD)
            msg.actions.append(action)
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)

        
        eth = packet.find("ethernet")
        if eth:
            log.info(f"Ethernet: src={eth.src}, dst={eth.dst}, type={hex(eth.type)}")

        # IPv4 Layer
        ip_pkt = packet.find("ipv4")
        if ip_pkt:
            log.info(f"IPv4: src={ip_pkt.srcip}, dst={ip_pkt.dstip}, proto={ip_pkt.protocol}")

        latency = 0
        # Chỉ xử lý TCP Port 44818 (ENIP)
        tcp_pkt = packet.find("tcp")

        #arp valid
        sender_ip = str(packet.payload.protosrc)
        sender_mac = str(packet.payload.hwsrc)

        if sender_ip in VALID_IP_TO_MAC:
            # Internal attack
            if sender_mac != VALID_IP_TO_MAC[sender_ip]:
                # Internal attack
                if sender_mac in VALID_IP_TO_MAC.values():
                    for key, value in VALID_IP_TO_MAC.items():
                        if value == sender_mac:
                            attacker_ip = key
                    log("Internal attack")
                    # log.warning(
                    #     "%d internal ap detected: %s MAC with %s IP "
                    #     "tries to impersonate %s IP with %s MAC" % (
                    #         event.dpid, sender_mac, attacker_ip,
                    #         sender_ip,  VALID_IP_TO_MAC[sender_ip]))
                # External attack
                else:
                    log("External attack")
                    # log.warning(
                    #     "%d external ap detected: %s MAC tries to "
                    #     "impersonate %s IP with %s MAC" % (
                    #         event.dpid, sender_mac, sender_ip,
                    #          VALID_IP_TO_MAC[sender_ip]))
        # Cập nhật thống kê băng thông
        bw = 0
        
        if ip_pkt:
            now = time.time()
            pkt_len = len(packet)
            conn_key = (str(ip_pkt.srcip), str(ip_pkt.dstip))
            if conn_key not in latency_list:
                latency_list[conn_key] = 0
            if conn_key not in bandwidth_tracker:
                bandwidth_tracker[conn_key] = [pkt_len, now]
            else:
                prev_bytes, prev_time = bandwidth_tracker[conn_key]
                time_diff = now - prev_time
                if time_diff > 0:
                    bw = (pkt_len * 8) / time_diff  # băng thông tính bằng bit/s
                    bandwidth_list[conn_key] = bw
                    if conn_key not in ema_bandwidth:
                        ema_bandwidth[conn_key] = bw
                    else:
                        ema_bandwidth[conn_key] = alpha * bw + (1 - alpha) * ema_bandwidth[conn_key]
                    log.info(f"[Bandwidth] {conn_key[0]} -> {conn_key[1]}: {bw:.2f} bps")
                bandwidth_tracker[conn_key] = [pkt_len, now]
        latency = 0
        if tcp_pkt:
            if tcp_pkt.dstport == 44818:
                log.info(f"ENIP Packet Detected: src_port={tcp_pkt.srcport}, dst_port={tcp_pkt.dstport}")
                session_id = f"{ip_pkt.srcip},{ip_pkt.dstip},{tcp_pkt.srcport}"
                payload = bytes(tcp_pkt.payload)
                log.info(f"TCP Payload: {payload}")
                cip_latency_tracker[session_id] = time.time()
            if tcp_pkt.srcport == 44818:
                log.info(f"ENIP Packet Detected: src_port={tcp_pkt.srcport}, dst_port={tcp_pkt.dstport}")
                session_id = f"{ip_pkt.dstip},{ip_pkt.srcip},{tcp_pkt.dstport}"
                current_time = time.time()
                if session_id in cip_latency_tracker:
                    previous_time = cip_latency_tracker[session_id]
                    latency = current_time - previous_time
                    key = (str(ip_pkt.dstip), str(ip_pkt.srcip))
                    key_down = (str(ip_pkt.srcip), str(ip_pkt.dstip))
                    latency_list[key] = latency
                    latency_list[key_down] = latency
                    if key not in ema_latency:
                        ema_latency[key] = latency
                    else:
                        ema_latency[key] = alpha * latency + (1 - alpha) * ema_latency[key]
                        ema_latency[key_down] = alpha * latency + (1 - alpha) * ema_latency[key_down]


                    log.info("============================================================")
                    log.info(f"[CIP] Session {session_id} - Latency: {latency:.6f} seconds")
                    metrics = {
                            "srcip": str(ip_pkt.dstip),
                            "dstip": str(ip_pkt.srcip),
                            "latency": latency,
                            "ema_latency": ema_latency[key],
                            "bandwidth": bandwidth_list[key],
                            "ema_bandwidth": ema_bandwidth[key],
                            "timestamp": time.time()
                            }
                    send_metrics_to_dashboard(metrics)
                    del cip_latency_tracker[session_id]

        now = time.time()
        for sid in list(cip_latency_tracker):
            if now - cip_latency_tracker[sid] > 10:
                del cip_latency_tracker[sid]

        if ip_pkt:
            metrics = {
                "srcip": str(ip_pkt.srcip),
                "dstip": str(ip_pkt.dstip),
                "latency": latency_list[conn_key],
                "ema_latency": ema_latency[key],
                "bandwidth": bw,
                "ema_bandwidth": ema_bandwidth[conn_key],
                "timestamp": time.time()
                }
            send_metrics_to_dashboard(metrics)
        log.info("==============================")
        if packet.dst.is_multicast:
            flood()
        else:
            if packet.dst not in self.macToPort:
                flood("Port from %s unknown -- flooding" % (packet.dst))
            else:
                port = self.macToPort[packet.dst]
                if port == event.port:
                    log.warning("Same port for packet from %s -> %s on .%s.  Drop."
                            % (packet.src, packet.dst, port))
                    drop()
                    return
                log.debug("installing flow for %s.%i -> %s.%i"
                    % (packet.src, event.port, packet.dst, port))
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet, event.port)
                msg.idle_timeout = 10
                msg.hard_timeout = 30
                action = of.ofp_action_output(port=port)
                msg.actions.append(action)
                msg.data = event.ofp
                self.connection.send(msg)
        

def launch():
    """
    Khởi chạy POX controller.
    """
    def start_switch(event):
        log.info(f"Switch {event.connection.dpid} has connected")
        AntiARPCachePoisoning(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)

    threading.Thread(target=start_udp_server, daemon=True).start()
    log.info("Anti ARP Cache Poisoning Controller is running")