from scapy.all import *
from M2Crypto import X509

def decode_serverhello(packet):
    payload = packet.load
    cert = payload[94:1141]
    cert = X509.load_cert_string(cert, 0)
    return cert

def get_pubkey(cert):
    pubkey = cert.get_pubkey().get_rsa()
    n = long(pubkey.n.encode('hex')[8:], 16)
    e = long(pubkey.e.encode('hex')[9:], 16)
    return n, e

packets = rdpcap('ssl.pcap')
cert = decode_serverhello(packets[15])
n,e = get_pubkey(cert)