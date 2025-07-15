import socket
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime

import netifaces

from compression_encryption import SecureGOOSEMessaging
from ied_utils import getIPv4Add
from parse_sed import parse_sed

# --- Constants from Sender ---
HEADER_LENGTH = 18  # Length of the PDU header
NONCE_SIZE = 12    # Nonce size for AES-GCM in bytes
TAG_SIZE = 16      # Tag size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes

# --- Data Structures ---
@dataclass
class ReceivedPacket:
    """Represents a received IEC 61850 packet (GOOSE or SV)"""
    packet_type: str  # 'GOOSE' or 'SV'
    appid: int
    length: int
    timestamp: float
    multicast_ip: str
    
    # GOOSE specific fields
    gocb_ref: str = None
    time_allowed_to_live: int = None
    dat_set: str = None
    go_id: str = None
    st_num: int = None
    sq_num: int = None
    test: bool = None
    conf_rev: int = None
    nds_com: bool = None
    num_dat_set_entries: int = None
    data_values: list = None
    
    # SV specific fields
    svid: str = None
    smp_cnt: int = None
    smp_synch: int = None
    sample_data: list = None

# --- Global Statistics Tracking ---
class Statistics:
    """Tracks transmission statistics for GOOSE and SV packets"""
    def __init__(self):
        self.total_transmission_time_goose = 0.0
        self.total_packets_goose = 0
        self.total_transmission_time_sv = 0.0
        self.total_packets_sv = 0
        self.total_decrypt_time = 0.0
        self.total_hmac_time = 0.0
        self.total_packets = 0
    
    def update_goose_stats(self, transmission_time, decrypt_time, hmac_time):
        """Update GOOSE packet statistics"""
        self.total_packets_goose += 1
        self.total_transmission_time_goose += transmission_time
        self.total_decrypt_time += decrypt_time
        self.total_hmac_time += hmac_time
        self.total_packets += 1
        
    def update_sv_stats(self, transmission_time, decrypt_time, hmac_time):
        """Update SV packet statistics"""
        self.total_packets_sv += 1
        self.total_transmission_time_sv += transmission_time
        self.total_decrypt_time += decrypt_time
        self.total_hmac_time += hmac_time
        self.total_packets += 1
    
    def get_avg_goose_time(self):
        """Get average GOOSE transmission time in ms"""
        if self.total_packets_goose == 0:
            return 0
        return self.total_transmission_time_goose / self.total_packets_goose
    
    def get_avg_sv_time(self):
        """Get average SV transmission time in ms"""
        if self.total_packets_sv == 0:
            return 0
        return self.total_transmission_time_sv / self.total_packets_sv
    
    def get_avg_decrypt_time(self):
        """Get average decryption time in ms"""
        if self.total_packets == 0:
            return 0
        return self.total_decrypt_time / self.total_packets
    
    def get_avg_hmac_time(self):
        """Get average HMAC verification time in ms"""
        if self.total_packets == 0:
            return 0
        return self.total_hmac_time / self.total_packets

# --- Network Functions ---
def join_multicast_group(sock, multicast_ip, interface_name):
    """Join a multicast group on specified interface"""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 102))  # Port 102 as per sender
    addrs = netifaces.ifaddresses(interface_name)
    if netifaces.AF_INET not in addrs:
        print(f"No IPv4 address found for interface {interface_name}")
        sys.exit(1)
    addr = addrs[netifaces.AF_INET][0]['addr']
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, 
                    socket.inet_aton(addr))
    mreq = struct.pack('4s4s', socket.inet_aton(multicast_ip),
                      socket.inet_aton(addr))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

# --- ASN.1 Decoding Utilities ---
def decode_asn1_length(data, offset):
    """Decode ASN.1 length field and return (length, new_offset)"""
    if offset >= len(data):
        return 0, offset
    length = data[offset]
    new_offset = offset + 1
    if length & 0x80:
        length_bytes = length & 0x7F
        if new_offset + length_bytes > len(data):
            return 0, offset
        length = 0
        for i in range(length_bytes):
            length = (length << 8) | data[new_offset]
            new_offset += 1
    return length, new_offset

def safe_get_bytes(data, start, length):
    """Safely get bytes from data with bounds checking"""
    if start + length > len(data):
        return None
    return data[start:start + length]

# --- Packet Decoders ---
def decode_goose_pdu(data, offset):
    """Decode GOOSE PDU and return packet info"""
    try:
        packet = ReceivedPacket(
            packet_type='GOOSE', 
            appid=0, 
            length=0, 
            timestamp=time.time(),
            multicast_ip=''
        )
        if offset >= len(data):
            return packet
        pdu_len, offset = decode_asn1_length(data, offset + 1)
        while offset < len(data):
            tag = data[offset]
            offset += 1
            length, offset = decode_asn1_length(data, offset)
            if offset + length > len(data):
                break
            if tag == 0x80:  # gocbRef
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.gocb_ref = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x81:  # timeAllowedToLive
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.time_allowed_to_live = int.from_bytes(bytes_data, 'big')
            elif tag == 0x82:  # datSet
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.dat_set = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x83:  # goID
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.go_id = bytes_data.decode('utf-8', errors='ignore')
            elif tag == 0x84:  # timestamp
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data and len(bytes_data) == 8:
                    packet.timestamp = struct.unpack('>d', bytes_data)[0]
            elif tag == 0x85:  # stNum
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.st_num = int.from_bytes(bytes_data, 'big')
            elif tag == 0x86:  # sqNum
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.sq_num = int.from_bytes(bytes_data, 'big')
            elif tag == 0x87:  # test
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.test = bool(bytes_data[0])
            elif tag == 0x88:  # confRev
                bytes_data = safe_get_bytes(data, offset, length)
                if bytes_data:
                    packet.conf_rev = int.from_bytes(bytes_data, 'big')
            elif tag == 0x89:  # ndsCom
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.nds_com = bool(bytes_data[0])
            elif tag == 0x8A:  # numDatSetEntries
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    packet.num_dat_set_entries = bytes_data[0]
            elif tag == 0xAB:  # allData
                packet.data_values = []
                data_offset = offset
                while data_offset < offset + length and data_offset < len(data):
                    value_tag = data[data_offset]
                    data_offset += 1
                    value_len, data_offset = decode_asn1_length(data, data_offset)
                    if value_tag == 0x83 and data_offset < len(data):  # Boolean
                        packet.data_values.append(bool(data[data_offset]))
                    data_offset += value_len
            offset += length
        return packet
    except Exception as e:
        print(f"Error decoding GOOSE PDU: {e}")
        return None

def decode_sv_pdu(data, offset):
    """Decode Sampled Values PDU and return packet info"""
    try:
        packet = ReceivedPacket(
            packet_type='SV',
            appid=0, 
            length=0,
            timestamp=time.time(),
            multicast_ip=''
        )
        if offset >= len(data):
            return packet
        pdu_len, offset = decode_asn1_length(data, offset + 1)
        while offset < len(data):
            tag = data[offset]
            offset += 1
            length, offset = decode_asn1_length(data, offset)
            if offset + length > len(data):
                break
            if tag == 0x80:  # noASDU
                bytes_data = safe_get_bytes(data, offset, 1)
                if bytes_data:
                    no_asdu = bytes_data[0]
            elif tag == 0xA2:  # seqOfASDU
                asdu_offset = offset
                while asdu_offset < offset + length and asdu_offset < len(data):
                    if data[asdu_offset] == 0x30:  # ASDU
                        asdu_len, asdu_offset = decode_asn1_length(data, asdu_offset + 1)
                        inner_offset = asdu_offset
                        while inner_offset < asdu_offset + asdu_len and inner_offset < len(data):
                            inner_tag = data[inner_offset]
                            inner_offset += 1
                            inner_len, inner_offset = decode_asn1_length(data, inner_offset)
                            if inner_offset + inner_len > len(data):
                                break
                            if inner_tag == 0x80:  # svID
                                bytes_data = safe_get_bytes(data, inner_offset, inner_len)
                                if bytes_data:
                                    packet.svid = bytes_data.decode('utf-8', errors='ignore')
                            elif inner_tag == 0x82:  # smpCnt
                                bytes_data = safe_get_bytes(data, inner_offset, inner_len)
                                if bytes_data:
                                    packet.smp_cnt = int.from_bytes(bytes_data, 'big')
                            elif inner_tag == 0x85:  # smpSynch
                                bytes_data = safe_get_bytes(data, inner_offset, 1)
                                if bytes_data:
                                    packet.smp_synch = bytes_data[0]
                            elif inner_tag == 0x87:  # seqOfData
                                packet.sample_data = []
                                sample_offset = inner_offset
                                while sample_offset + 4 <= inner_offset + inner_len:
                                    bytes_data = safe_get_bytes(data, sample_offset, 4)
                                    if bytes_data:
                                        value = struct.unpack('>f', bytes_data)[0]
                                        packet.sample_data.append(value)
                                    sample_offset += 4
                            elif inner_tag == 0x89:  # timestamp
                                bytes_data = safe_get_bytes(data, inner_offset, inner_len)
                                if bytes_data and len(bytes_data) == 8:
                                    packet.timestamp = struct.unpack('>d', bytes_data)[0]
                            inner_offset += inner_len
                        asdu_offset += asdu_len
                    else:
                        asdu_offset += 1
            offset += length
        return packet
    except Exception as e:
        print(f"Error decoding SV PDU: {e}")
        return None

# --- Display Functions ---
def display_packet_info(packet, stats):
    """Display received packet information with statistics"""
    if not packet:
        return
    print("\n" + "="*80)
    print(f"Received {packet.packet_type} Packet from {packet.multicast_ip}")
    print(f"Packet Timestamp: {datetime.fromtimestamp(packet.timestamp)}")
    current_datetime = time.time()
    print("Current Timestamp:", datetime.fromtimestamp(current_datetime))
    time_difference_ms = (current_datetime - packet.timestamp) * 1000
    print("Transmission time:", round(time_difference_ms, 6), "ms")
    print(f"APPID: 0x{packet.appid:04x}")
    print(f"Length: {packet.length} bytes")
    print(f"Average Decryption time: {stats.get_avg_decrypt_time():.6f} ms")
    print(f"Average HMAC verification time: {stats.get_avg_hmac_time():.6f} ms")
    if packet.packet_type == 'GOOSE':
        print("Average GOOSE Transmission time:", stats.get_avg_goose_time())
        print("\nGOOSE Specific Information:")
        if packet.gocb_ref: print(f"GoCB Reference: {packet.gocb_ref}")
        if packet.time_allowed_to_live: print(f"Time Allowed to Live: {packet.time_allowed_to_live}ms")
        if packet.dat_set: print(f"Dataset: {packet.dat_set}")
        if packet.go_id: print(f"GoID: {packet.go_id}")
        if packet.st_num is not None: print(f"StNum: {packet.st_num}")
        if packet.sq_num is not None: print(f"SqNum: {packet.sq_num}")
        if packet.test is not None: print(f"Test: {packet.test}")
        if packet.conf_rev is not None: print(f"ConfRev: {packet.conf_rev}")
        if packet.nds_com is not None: print(f"NdsCom: {packet.nds_com}")
        if packet.num_dat_set_entries is not None: print(f"Number of Dataset Entries: {packet.num_dat_set_entries}")
        if packet.data_values: print(f"Data Values: {packet.data_values}")
    elif packet.packet_type == 'SV':
        print("Average SV Transmission time:", stats.get_avg_sv_time())
        print("\nSampled Values Specific Information:")
        if packet.svid: print(f"svID: {packet.svid}")
        if packet.smp_cnt is not None: print(f"Sample Count: {packet.smp_cnt}")
        if packet.smp_synch is not None: print(f"Sample Sync: {packet.smp_synch}")
        if packet.sample_data:
            print("\nSample Values:")
            for i, value in enumerate(packet.sample_data):
                print(f"  Sample {i}: {value}")

# --- Packet Processing ---
def get_peer_from_ip(multicast_ip, known_peers, vector_of_ctrl_blks, ied_name):
    """Map multicast IP to peer ID (placeholder implementation)"""
    for it in vector_of_ctrl_blks:
        if it.multicastIP == multicast_ip and it.hostIED != ied_name:
            return it.hostIED
    return known_peers[0] if known_peers else ""  # Fallback to first peer or empty string

def process_received_data(data, addr, stats, secure_messaging, peer_id, vector_of_ctrl_blks, ied_name):
    """Process received data and extract packet information"""
    if len(data) < 32:  # Minimum length for headers + HMAC
        print("Packet too short, discarding")
        return
    try:
        offset = 2  # Skip LI and TI bytes
        packet_type = data[offset]
        offset += 1
        offset += 1  # Skip LI byte
        if offset >= len(data) or data[offset] != 0x80:
            print("Invalid session header")
            return
        offset += 2  # Skip PI and LI
        offset += 8  # Skip SPDU length and number
        offset += 2  # Skip version number
        if offset + 12 > len(data):
            print("Packet too short for header fields")
            return
        timestamp = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        key_rotation_minutes = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2
        encryption_algorithm = data[offset:offset+1]
        offset += 1
        message_auth_algorithm = data[offset:offset+1]
        offset += 1
        key_id = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        if offset + 4 >= len(data):
            print("Packet too short for payload length")
            return
        payload_len = int.from_bytes(data[offset:offset+4], 'big')
        offset += 4
        if offset + 6 >= len(data):
            print("Packet too short for payload")
            return
        payload_type = data[offset]
        simulation = data[offset + 1]
        appid = int.from_bytes(data[offset+2:offset+4], 'big')
        length = int.from_bytes(data[offset+4:offset+6], 'big')
        offset += 6
        if len(data) < offset + 32:  # Ensure enough data for HMAC
            print("Packet too short for HMAC")
            return
        hmac_tag = data[-32:]  # Last 32 bytes for HMAC-SHA256
        payload = data[offset:-32]
        headers = data[:offset]
        known_peers = ["SubstationA", "SubstationB", "SubstationC", "SubstationD"]
    
        # Determine peer ID from sender IP
        peer_id = get_peer_from_ip(addr[0], [peer for peer in known_peers], vector_of_ctrl_blks, ied_name)
        if not peer_id:
            print(f"No peer found for IP {addr[0]}, using default")
        # Verify HMAC and process payload
        t1 = time.time()
        try:
            expected_hmac = secure_messaging.generate_quantum_hmac(bytes(data[:-32]), peer_id)
            if hmac_tag != expected_hmac:
                print(f"Warning: QKE HMAC mismatch for peer {peer_id}")
                return
        except Exception as e:
            print(f"HMAC verification failed for peer {peer_id}: {e}")
            return
        hmac_time = (time.time() - t1) * 1000
        start_time = time.time() * 1000
        try:
            if encryption_algorithm == b'\x03':  # QKE-AES-GCM
                decrypted_payload = secure_messaging.receive_goose_message(
                    bytes(payload), peer_id, encrypted=True
                )
            else:
                decrypted_payload = secure_messaging.receive_goose_message(
                    bytes(payload), peer_id, encrypted=False
                )
        except Exception as e:
            print(f"QKE decryption error for peer {peer_id}: {e}")
            return
        decrypt_time = (time.time() * 1000) - start_time
        reconstructed_data = headers + list(decrypted_payload) + list(hmac_tag)
        reconstructed_data = bytearray(reconstructed_data)
        packet = None
        if payload_type == 0x81:  # GOOSE
            packet = decode_goose_pdu(reconstructed_data, offset)
            if packet:
                stats.update_goose_stats((time.time() - packet.timestamp) * 1000, decrypt_time, hmac_time)
        elif payload_type == 0x82:  # SV
            packet = decode_sv_pdu(reconstructed_data, offset)
            if packet:
                stats.update_sv_stats((time.time() - packet.timestamp) * 1000, decrypt_time, hmac_time)
        if packet:
            packet.appid = appid
            packet.length = length
            packet.multicast_ip = addr[0]
            display_packet_info(packet, stats)
    except Exception as e:
        print(f"Error processing packet: {e}")

# --- Main Function ---
def main():
    if len(sys.argv) != 4:
        program_name = sys.argv[0] if sys.argv and sys.argv[0] else "<program name>"
        print(f"Usage: {program_name} <SED Filename> <Interface Name to be used on IED> <IED Name>")
        return 1
    sed_filename = sys.argv[1]
    interface_name = sys.argv[2]
    ied_name = sys.argv[3]
    ifr = getIPv4Add(interface_name)
    ifr = socket.inet_pton(socket.AF_INET, ifr)
    # Initialize QKE secure messaging
    print("=== Initializing QKE Secure Messaging ===")
    secure_messaging = SecureGOOSEMessaging(ied_name)
    # Define known peers (same as sender)
    known_peers = ["SubstationA", "SubstationB", "SubstationC", "SubstationD"]
    if ied_name in known_peers:
        known_peers.remove(ied_name)
    print("Establishing quantum keys with peers...")
    for peer in known_peers:
        try:
            key = secure_messaging.qke.establish_quantum_key(peer)
            print(f"✓ Established quantum key with {peer}")
        except Exception as e:
            print(f"✗ Failed to establish key with {peer}: {e}")
    # Test QKE encryption/decryption
    if known_peers:
        test_peer = known_peers[0]
        try:
            demo_data = bytes([123])
            encrypted_demo = secure_messaging.encrypt_message(demo_data, test_peer)
            decrypted_demo = secure_messaging.decrypt_message(encrypted_demo, test_peer)
            print(f"✓ QKE test successful with {test_peer}")
        except Exception as e:
            print(f"✗ QKE test failed: {e}")
    # Parse SED file to get multicast IP
    multicast_ip = None
    vector_of_ctrl_blks = parse_sed(sed_filename)
    for it in vector_of_ctrl_blks:
        if it.hostIED == ied_name:
            multicast_ip = it.multicastIP
            break
    if not multicast_ip:
        print(f"Error: No multicast IP found for IED {ied_name}")
        return 1
    stats = Statistics()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        join_multicast_group(sock, multicast_ip, interface_name)
        print(f"Listening for QKE-secured RGOOSE/RSV packets on {interface_name} ({multicast_ip})...")
        # Key refresh timer
        last_key_refresh = time.time()
        key_refresh_interval = 1800  # 30 minutes, matching sender
        while True:
            if time.time() - last_key_refresh > key_refresh_interval:
                print("Refreshing quantum keys...")
                for peer in known_peers:
                    try:
                        secure_messaging.qke.refresh_key(peer)
                        print(f"✓ Refreshed quantum key with {peer}")
                    except Exception as e:
                        print(f"✗ Failed to refresh key with {peer}: {e}")
                last_key_refresh = time.time()
            data, addr = sock.recvfrom(65535)
            process_received_data(data, addr, stats, secure_messaging, None, vector_of_ctrl_blks, ied_name)
            # Print QKE status
            print("=== QKE Status ===")
            active_keys = 0
            for peer in known_peers:
                key_info = secure_messaging.qke._load_key_from_file(peer)
                if key_info:
                    active_keys += 1
                    key_age = time.time() - key_info['timestamp']
                    print(f"  {peer}: Key seq={key_info['sequence']}, age={key_age:.0f}s")
            print(f"Active quantum keys: {active_keys}")
            print("==================")
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        sock.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())