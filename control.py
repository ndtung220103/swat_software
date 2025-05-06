from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
import time
log = core.getLogger()

# Danh sách ánh xạ IP-to-MAC hợp lệ
VALID_IP_TO_MAC = {
    "192.168.1.10": "00:1d:9c:c7:b0:10",  # plc1
    "192.168.1.20": "00:1d:9c:c8:bc:20",  # hmi
    "192.168.1.77": "aa:aa:aa:aa:aa:aa",  # attacker (ví dụ)
}

cip_latency_tracker = {}
bandwidth_tracker = {}

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

        
        # Chỉ xử lý TCP Port 44818 (ENIP)
        tcp_pkt = packet.find("tcp")
        if tcp_pkt and tcp_pkt.dstport == 44818:
            log.info(f"ENIP Packet Detected: src_port={tcp_pkt.srcport}, dst_port={tcp_pkt.dstport}")
            session_id = f"{ip_pkt.srcip}:{tcp_pkt.srcport} -> {ip_pkt.dstip}:{tcp_pkt.dstport}"
            payload = bytes(tcp_pkt.payload)
            log.info(f"TCP Payload: {payload}")
            cip_latency_tracker[session_id] = time.time()
            if len(payload) >= 24:  # ENIP Header có ít nhất 24 bytes
                 command = int.from_bytes(payload[0:2], byteorder='little')
                 session = int.from_bytes(payload[4:8], byteorder='little')
                 log.info(f"ENIP Command: {hex(command)}, Session Handle: {session}")

                    # CIP Payload (sau header 24 bytes)
                 cip_payload = payload[24:]
                 if cip_payload:
                    log.info(f"CIP Data: {cip_payload.hex()}")  # In ra dạng hex
                    current_time = time.time()
                    if session_id in cip_latency_tracker:
                        previous_time = cip_latency_tracker[session_id]
                        latency = current_time - previous_time
                        log.info(f"[CIP] Session {session_id} - Latency: {latency:.6f} seconds")
                    

                    # Cập nhật timestamp
                    cip_latency_tracker[session_id] = current_time

        # Cập nhật thống kê băng thông
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
    log.info("Anti ARP Cache Poisoning Controller is running")