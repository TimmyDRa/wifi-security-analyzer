# Test just one detection type quickly
from intrusion_detection import process_packet
from utils import alert
from scapy.all import IP, TCP
import time

print('Testing port scan detection...')
# Generate fake port scan
for port in range(1, 55):
    fake_packet = IP(src='192.168.1.100', dst='192.168.1.1') / TCP(dport=port)
    process_packet(fake_packet)

print('Port scan test completed - check alerts!')