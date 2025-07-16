import sys
import socket
import struct
import time
import os
from ied_utils import *
from udpSock import *
from zz_diagnose import *
from parse_sed import *

from compression_encryption import compress_data, encrypt_aes_gcm, decrypt_aes_gcm, generate_hmac_cryptography, initialise_key

HEADER_LENGTH = 18  # Length of the PDU header
NONCE_SIZE = 12  # Nonce size for AES-GCM in bytes
TAG_SIZE = 16  # Tag size for AES-GCM in bytes
AES_KEY_SIZE = 32  # AES-256 key size in bytes

IEDUDPPORT = 102

from form_pdu import form_goose_pdu, form_sv_pdu

total_encrypt_time = 0
total_packets = 0

def main(argv):
    if len(argv) != 4:
        if argv[0]:
            print(f"Usage: {argv[0]} <SED Filename> <Interface Name to be used on IED> <IED Name>")
        else:
            print("Usage: <program name> <SED Filename> <Interface Name to be used on IED> <IED Name>")
        return 1

    # Specify SED Filename
    sed_filename = argv[1]
    
    # Specify Network Interface Name to be used on IED
    ifname = argv[2]
    
    # Save IPv4 address of specified Network Interface
    ifr = getIPv4Add(ifname)
    ifr = socket.inet_pton(socket.AF_INET, ifr)

    # Specify IED name
    ied_name = argv[3]

    # Initialize QKE secure messaging system
    print("=== Initializing QKE Secure Messaging ===")
    secure_messaging = SecureGOOSEMessaging(ied_name)  # Use ied_name for node_id
    
    # Define known peers for quantum key establishment
    known_peers = ["SubstationA", "SubstationB", "SubstationC", "SubstationD"]
    
    # Remove self from peers list
    if ied_name in known_peers:
        known_peers.remove(ied_name)
    
    # Establish quantum keys with all known peers
    print("Establishing quantum keys with peers...")
    for peer in known_peers:
        try:
            key = secure_messaging.qke.establish_quantum_key(peer)
            print(f"✓ Established quantum key with {peer}")
        except Exception as e:
            print(f"✗ Failed to establish key with {peer}: {e}")

    # Parse SED file
    vector_of_ctrl_blks = parse_sed(sed_filename)

    # Find relevant Control Blocks pertaining to IED
    ownControlBlocks = []
    goose_counter = 0
    sv_counter = 0

    namespace = '{http://www.iec.ch/61850/2003/SCL}'

    for it in vector_of_ctrl_blks:
        if it.hostIED == ied_name:
            if it.cbType == f'{namespace}GSE':
                goose_counter += 1
                tmp_goose_data = GooseSvData()
                
                tmp_goose_data.cbName = it.cbName
                tmp_goose_data.cbType = it.cbType
                tmp_goose_data.appID = it.appID
                tmp_goose_data.multicastIP = it.multicastIP
                tmp_goose_data.datSetName = it.datSetName
                tmp_goose_data.goose_counter = goose_counter

                ownControlBlocks.append(tmp_goose_data)
            
            elif it.cbType == f"{namespace}SMV":
                sv_counter += 1
                tmp_sv_data = GooseSvData()
                
                tmp_sv_data.cbName = it.cbName
                tmp_sv_data.cbType = it.cbType
                tmp_sv_data.appID = it.appID
                tmp_sv_data.multicastIP = it.multicastIP
                tmp_sv_data.sv_counter = sv_counter

                ownControlBlocks.append(tmp_sv_data)
    
    # Test QKE encryption/decryption
    print("Testing QKE encryption/decryption...")
    if known_peers:
        test_peer = known_peers[0]
        try:
            demo_data = bytes([123])
            encrypted_demo = secure_messaging.encrypt_message(demo_data, test_peer)
            decrypted_demo = secure_messaging.decrypt_message(encrypted_demo, test_peer)
            print(f"✓ QKE test successful with {test_peer}")
        except Exception as e:
            print(f"✗ QKE test failed: {e}")
    
    # Keep looping to send multicast messages
    s_value = 0
    initialise_key()
    
    while True:
        time.sleep(1)  # in seconds
        
        # Check if quantum keys need refresh
        current_time = time.time()
        if current_time - last_key_refresh > key_refresh_interval:
            print("Refreshing quantum keys...")
            for peer in known_peers:
                try:
                    secure_messaging.qke.refresh_key(peer)
                    print(f"✓ Refreshed quantum key with {peer}")
                except Exception as e:
                    print(f"✗ Failed to refresh key with {peer}: {e}")
            last_key_refresh = current_time

        # Form network packet for each Control Block
        for i in range(len(ownControlBlocks)):
            payload = []
            pdu_1 = []

            if ownControlBlocks[i].cbType == f"{namespace}GSE":
                print("cbName", ownControlBlocks[i].cbName)
                ownControlBlocks[i].s_value = s_value
                form_goose_pdu(ownControlBlocks[i], pdu_1)
                payload.append(0x81)

            elif ownControlBlocks[i].cbType == f"{namespace}SMV":
                print("cbName", ownControlBlocks[i].cbName)
                ownControlBlocks[i].s_value = s_value
                form_sv_pdu(ownControlBlocks[i], pdu_1)
                payload.append(0x82)

            payload.append(0x00)  # Simulation 0x00: Boolean False
            raw_converted_appid = int(ownControlBlocks[i].appID, 16)
            payload.append((raw_converted_appid >> 8) & 0xFF)
            payload.append(raw_converted_appid & 0xFF)
            apdu_len = len(pdu_1) + 2
            payload.append((apdu_len >> 8) & 0xFF)
            payload.append(apdu_len & 0xFF)
            payload.extend(pdu_1)
            
            udp_data = []
            udp_data.append(0x01)  # Length Identifier (LI)
            udp_data.append(0x40)  # Transport Identifier (TI)

            if ownControlBlocks[i].cbType == f"{namespace}GSE":
                udp_data.append(0xA1)
            elif ownControlBlocks[i].cbType == f"{namespace}SMV":
                udp_data.append(0xA2)

            udp_data.append(0x18)  # Length Identifier (LI)
            udp_data.append(0x80)  # Parameter Identifier (PI)
            udp_data.append(0x16)  # Length Identifier (LI)

            spdu_length = (4 + 2) + 12 + 4 + len(payload) + 2
            udp_data.append((spdu_length >> 24) & 0xFF)
            udp_data.append((spdu_length >> 16) & 0xFF)
            udp_data.append((spdu_length >> 8) & 0xFF)
            udp_data.append(spdu_length & 0xFF)

            current_SPDUNum = ownControlBlocks[i].prev_spduNum
            ownControlBlocks[i].prev_spduNum += 1
            udp_data.append((current_SPDUNum >> 24) & 0xFF)
            udp_data.append((current_SPDUNum >> 16) & 0xFF)
            udp_data.append((current_SPDUNum >> 8) & 0xFF)
            udp_data.append(current_SPDUNum & 0xFF)

            udp_data.append(0x00)
            udp_data.append(0x01)
            
            timestamp = int(time.time()).to_bytes(4, 'big')
            udp_data.extend(timestamp)
            key_rotation_minutes = (60).to_bytes(2, 'big')
            udp_data.extend(key_rotation_minutes)
            
            encryption_algorithm = b'\x03'  # QKE-AES-GCM
            message_auth_algorithm = b'\x03'  # QKE-HMAC-SHA256
            udp_data.extend(encryption_algorithm)
            udp_data.extend(message_auth_algorithm)
            
            # Use quantum key sequence number as key ID
            target_peer = known_peers[0] if known_peers else None
            if target_peer:
                key_info = secure_messaging.qke._load_key_from_file(target_peer)
                if key_info:
                    key_id = key_info['sequence'].to_bytes(4, 'big')
                else:
                    key_id = os.urandom(4)  # Fallback
            else:
                key_id = os.urandom(4)
            udp_data.extend(key_id)

            payload_len = len(payload) + 4
            udp_data.append((payload_len >> 24) & 0xFF)
            udp_data.append((payload_len >> 16) & 0xFF)
            udp_data.append((payload_len >> 8) & 0xFF)
            udp_data.append(payload_len & 0xFF)
            
            print(len(udp_data))
            print("Payload length before encryption/compression", len(payload))

            start_time = time.time()*1000
            payload = (compress_data(bytes(payload)))
            payload = (encrypt_aes_gcm(bytes(payload)))
            
            udp_data.extend(payload)

            # Signature Tag = 0x85                
            udp_data.append(0x85)
            
            # Length of HMAC 
            udp_data.append(0x20)

            t1  = time.time()
            udp_data.extend(generate_hmac_cryptography(udp_data))
            t2  = time.time()
            print("Mac generation time : ", t2-t1)

            sock = UdpSock()
            diagnose(sock.is_good(), "Opening datagram socket for send")

            groupSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            groupSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            try:
                groupSock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, ifr)
                print("Setting local Interface: ", ifname)
            except Exception as e:
                print("Error setting local interface:", e)

            try:
                TTL = 16
                groupSock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', TTL))
                current_ttl = struct.unpack('b', groupSock.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1))[0]
                print("TTL set to:", current_ttl)
            except Exception as e:
                print("Error setting multicast TTL:", e)

            try:
                groupSock.sendto(bytearray(udp_data), (ownControlBlocks[i].multicastIP, IEDUDPPORT))
                print(len(udp_data), "bytes Data sent to:", ownControlBlocks[i].multicastIP, "on port", IEDUDPPORT)
                print("✓ QKE-secured message sent successfully")
            except Exception as e:
                print("Error sending data:", e)

            # QKE status information
            print("=== QKE Status ===")
            active_keys = 0
            for peer in known_peers:
                key_info = secure_messaging.qke._load_key_from_file(peer)
                if key_info:
                    active_keys += 1
                    key_age = current_time - key_info['timestamp']
                    print(f"  {peer}: Key seq={key_info['sequence']}, age={key_age:.0f}s")
            print(f"Active quantum keys: {active_keys}")
            print("==================")
            
            print(udp_data)
            print('-------------------------------------------------------------------------------')
        s_value += 1
        print("Resend")
        print()
    return 0

if __name__ == "__main__":
    main(sys.argv)