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
    "192.168.1.10": "00:1d:9c:c7:b0:10",  # plc1
    "192.168.1.20": "00:1d:9c:c8:bc:20",  # hmi
    "192.168.1.77": "aa:aa:aa:aa:aa:aa",  # attacker (ví dụ)
}

cip_latency_tracker = {}
bandwidth_tracker = {}
sensor_data = {}

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
        if tcp_pkt and tcp_pkt.dstport == 44818:
            payload = bytes(tcp_pkt.payload)
            if len(payload) >= 24:
                command = int.from_bytes(payload[0:2], byteorder='little')
                session_handle = int.from_bytes(payload[4:8], byteorder='little')
                cip_payload = payload[24:]

                log.info(f"ENIP Command: {hex(command)}, Session Handle: {session_handle}")
                
                now = time.time()

                # Nếu chưa có session này, thì lưu lại timestamp (request)
                if session_handle not in cip_latency_tracker:
                    cip_latency_tracker[session_handle] = now
                    log.info(f"[CIP] Stored request timestamp for session {session_handle}")
                else:
                    # Nếu đã có, thì đây là response → tính latency
                    latency = now - cip_latency_tracker[session_handle]
                    log.info(f"[CIP] Latency for session {session_handle}: {latency:.6f} seconds")
                    del cip_latency_tracker[session_handle]

        for sid in list(cip_latency_tracker):
            if now - cip_latency_tracker[sid] > 10:
                del cip_latency_tracker[sid]
        # Cập nhật thống kê băng thông
        bw = 0

        if ip_pkt:
            conn_key = (str(ip_pkt.srcip), str(ip_pkt.dstip))
            now = time.time()
            pkt_len = len(packet)

            if conn_key not in bandwidth_tracker:
                bandwidth_tracker[conn_key] = [pkt_len, now]
            else:
                prev_bytes, prev_time = bandwidth_tracker[conn_key]
                time_diff = now - prev_time
                if time_diff > 0:
                    bw = (pkt_len * 8) / time_diff  # băng thông tính bằng bit/s
                    log.info(f"[Bandwidth] {conn_key[0]} -> {conn_key[1]}: {bw:.2f} bps")
                bandwidth_tracker[conn_key] = [pkt_len, now]
                
        if ip_pkt:
            metrics = {
                "srcip": str(ip_pkt.srcip),
                "dstip": str(ip_pkt.dstip),
                "latency": latency,
                "bandwidth": bw,
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