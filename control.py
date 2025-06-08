from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.recoco import Timer
import json
import time
import requests

log = core.getLogger()

# Danh sách ánh xạ IP-to-MAC hợp lệ
VALID_IP_TO_MAC = {
    '192.168.1.10': '00:1d:9c:c7:b0:10',
    '192.168.1.20': '00:1d:9c:c8:bc:20',
    '192.168.1.30': '00:1d:9c:c8:bd:30',
    '192.168.1.40': '00:1d:9c:c7:fa:40',
    '192.168.1.50': '00:1d:9c:c8:bc:50',
    '192.168.1.60': '00:1d:9c:c7:fa:60',
    '192.168.1.70': '00:1d:9c:c8:bc:70',
    '192.168.1.77': 'aa:aa:aa:aa:aa:aa'
}

sensor_data = {}
port_stats = {} 
flow_stats = {} 

def send_mess_to_dashboard(mess):
    try:
        url = "http://127.0.0.1:5000/mess"
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=mess)
    except Exception as e:
        log.error(f"[DASHBOARD] Exception: {e}")

class SwitchHandle (object):
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
        ip_pkt = packet.find("ipv4")
        tcp_pkt = packet.find("tcp")

        #arp valid
        if packet.type == eth.ARP_TYPE:
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
                        log.warning(
                            "%d internal ap detected: %s MAC with %s IP "
                            "tries to impersonate %s IP with %s MAC" % (
                                event.dpid, sender_mac, attacker_ip,
                                sender_ip,  VALID_IP_TO_MAC[sender_ip]))
                    # External attack
                    else:
                        log.warning(
                            "%d external ap detected: %s MAC tries to "
                            "impersonate %s IP with %s MAC" % (
                                event.dpid, sender_mac, sender_ip,
                                 VALID_IP_TO_MAC[sender_ip]))
        
        if packet.dst.is_multicast:
            flood()
        else:
            if packet.dst not in self.macToPort:
                flood()
            else:
                port = self.macToPort[packet.dst]
                if port == event.port:
                    log.warning("Same port for packet from %s -> %s on .%s.  Drop."
                            % (packet.src, packet.dst, port))
                    drop()
                    return
                # 
                if ip_pkt:
                    msg = of.ofp_flow_mod()
                    match = of.ofp_match()
                    match.dl_type = 0x0800
                    match.dl_src = eth.src
                    match.dl_dst = eth.dst
                    match.nw_src = ip_pkt.srcip
                    match.nw_dst = ip_pkt.dstip
                    msg.idle_timeout = 20
                    # msg.hard_timeout = 50
                    msg.match = match
                    action = of.ofp_action_output(port=port)
                    msg.actions.append(action)
                    msg.data = event.ofp
                    self.connection.send(msg)
                else:
                    msg = of.ofp_packet_out()
                    msg.data = event.ofp
                    msg.in_port = event.port
                    action = of.ofp_action_output(port=port)
                    msg.actions.append(action)
                    self.connection.send(msg)

def _handle_PortStatsReceived(event):
    log.info("=== Port Stats Received from Switch %s ===", event.connection.dpid)
    switch = int(event.connection.dpid)
    for stat in event.stats:
        key = f"{switch}_{stat.port_no}"
        stats = {
            "Time" : time.time(),
            "rx_packets": stat.rx_packets,
            "rx_bytes": stat.rx_bytes,
            "rx_dropped": stat.rx_dropped,
            "rx_errors": stat.rx_errors,
            "tx_packets": stat.tx_packets,
            "tx_bytes": stat.tx_bytes,
            "tx_dropped": stat.tx_dropped,
            "tx_errors": stat.tx_errors
        }
        port_stats[key] = stats
    try:
        requests.post("http://localhost:5000/port_stats", json=port_stats)
        print("[+] Sent port stats to dashboard.")
    except Exception as e:
        print("[!] Failed to send port stats:", e)

def _handle_FlowStatsReceived(event):
    log.info(f"Flow stats from switch {event.connection.dpid}")
    switch = int(event.connection.dpid)
    for flow in event.stats:
        key = f"{switch}_{flow.match.dl_src}_{flow.match.dl_dst}_{flow.match.nw_src}_{flow.match.nw_dst}"
        stats = {
            "Time" : time.time(),
            "Packets":  flow.packet_count,
            "Bytes": flow.byte_count,
            "Duration":  flow.duration_sec
        }
        flow_stats[key] = stats
    try:
        requests.post("http://localhost:5000/flow_stats", json=flow_stats)
        print("[+] Sent flow stats to dashboard.")
    except Exception as e:
        print("[!] Failed to send flow stats:", e)

def poll_stats():
    for connection in core.openflow._connections.values():
        # Lấy flow stats
        req1 = of.ofp_stats_request()
        req1.type = of.OFPST_FLOW
        req1.body = of.ofp_flow_stats_request()
        connection.send(req1)

        # Lấy port stats
        req2 = of.ofp_stats_request()
        req2.type = of.OFPST_PORT
        req2.body = of.ofp_port_stats_request(port_no=of.OFPP_NONE)
        connection.send(req2)      

def launch():
    """
    Khởi chạy POX controller.
    """
    def start_switch(event):
        log.info(f"Switch {event.connection.dpid} has connected")
        SwitchHandle(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    core.openflow.addListenerByName("PortStatsReceived", _handle_PortStatsReceived)
    core.openflow.addListenerByName("FlowStatsReceived", _handle_FlowStatsReceived)
    Timer(2, poll_stats, recurring=True) 
    log.info("Controller is running")