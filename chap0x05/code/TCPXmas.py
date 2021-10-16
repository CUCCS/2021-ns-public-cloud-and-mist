#攻击者主机编写tcpxmas.py
from scapy.all import *
def Xmasscan(dst_ip , dst_port , timeout = 10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=10)# 发送FIN,PUSH,URG
    if (pkts is None): # 未收到任何包可能为这两种状态
        print ("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print ("Closed") # 收到RST包即为端口关闭状态
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type)==3 and int(pkts.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print ("Filtered")
Xmasscan('172.16.111.142',80)