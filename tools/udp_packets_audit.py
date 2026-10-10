"""Count only test proxy UDP headers. Never output/store packet contents."""
import json
import socket
import struct
import time
incoming=outgoing=0
end=time.monotonic()+35
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)) as capture:
 capture.settimeout(1)
 while time.monotonic()<end:
  try:packet=capture.recv(65535)
  except socket.timeout:continue
  if len(packet)<42 or packet[12:14]!=b'\x08\x00' or packet[23]!=17:continue
  offset=14+(packet[14]&15)*4
  if len(packet)<offset+8:continue
  source,destination=struct.unpack('!HH',packet[offset:offset+4])
  if destination==51752:incoming+=1
  if source==51752:outgoing+=1
print(json.dumps({'incoming_proxy_udp_packets':incoming,'outgoing_proxy_udp_packets':outgoing}))
