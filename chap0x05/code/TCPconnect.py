# TCPconnect.py
from scapy.all import *
def tcpconnect(dst_ip,dst_port,timeout=10):
    pkts=sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=timeout)# 构造SYN包，flags='S'表示为SYN包
    if (pkts is None):
        print("FILTER")
    elif(pkts.haslayer(TCP)):
        if(pkts[1].flags=='AS'): # 收到的第一个包为回来的tcp包，若为ACK包，则表示处于开放状态
            print("OPEN")
        elif(pkts[1].flags=='AR'): # 若收到的第一个包为RST包，则表示为开放状态
                print("CLOSE")
tcpconnect('172.16.111.142',80)