# 第一章：基于VirtualBox的网络攻防基础环境搭建

## 实验目的

- 掌握 VirtualBox 虚拟机的安装与使用；
- 掌握 VirtualBox 的虚拟网络类型和按需配置；
- 掌握 VirtualBox 的虚拟硬盘多重加载；

## 实验环境

- VirtualBox虚拟机
- 攻击者主机（Attacker）：Kali Rolling 2109.2
- 网关（Gateway, GW）：Debian Buster
- 靶机（Victim）：From Sqli to shell / xp-sp3 / Kali

## 实验要求

- 虚拟硬盘配置成多重加载
- 搭建满足如下拓扑图所示的虚拟机网络拓扑；

![](img/network_topology.png)

- 完成以下网络连通性测试；
  - [x] 靶机可以直接访问攻击者主机
  - [x] 攻击者主机无法直接访问靶机
  - [x] 网关可以直接访问攻击者主机和靶机
  - [x] 靶机的所有对外上下行流量必须经过网关
  - [x] 所有节点均可以访问互联网

## 网络配置

1. 配置多重加载

   管理->虚拟介质管理->类型改为`多重加载`->释放盘片

   ![](img/Multiple_load.PNG)

2. 虚拟机配置结果

   - 两台kali:攻击者kali-attacker、靶机kali-victim-1

   - 两台xp:靶机xp-victim-1、靶机xp-victim-2

   - 两台Debian:网关Debian-gateway、靶机Debian-victim-2

     ![](img/virtual.PNG)

3. 网络配置

- 配置网关网络

  四块网卡：

  - NAT网络：网关可以访问攻击者主机
  - Host-only：方便使用ssh远程连上主机
  - 两个内部网络：搭建出两个独立的局域网，intnet1和intnet2

![](img/Debian-gateway-network.PNG)

```
#用户切换
sudo su root

#修改配置文件
vi /etc/network/interfaces

#重启
/sbin/ifup enp0s9
/sbin/ifup enp0s10
sudo systemctl restart networking

#安装dnsmasq
apt-get update  
apt-get install dnsmasq 

#修改/etc/dnsmasq.d/gw-enp09.conf
interface=enp0s9
dhcp-range=172.16.111.10,172.16.111.150,240h


#修改/etc/dnsmasq.d/gw-enp10.conf
interface=enp0s10
dhcp-range=172.16.222.10,172.16.222.150,240h

#备份dnsmasq.conf文件
cp dnsmasq.conf dnsmasq.conf.bak

#修改dnsmasq.conf文件
#log-dhcp--->log-dhcp
#log-queries--->log-queries
#在log-queries下面加一条命令
log-facility=/var/log/dnsmasq.log

#重启dnsmasq
/etc/init.d/dnsmasq restart
```

![](img/debian-gateway-network-card.png)

- 配置intnet1中的xp-victim-1

![](img/xp-victim-1-net.PNG)

生成的ip地址

![](img/xp-1-ip.PNG)

- 配置intnet1中的kali-victim-1

![](img/kali-victim-1-net.PNG)

生成的ip地址
![](img/kali-victim-1-ip.PNG)

- 配置intnet2中的xp-victim-2

![](img/xp-victim-2-net.PNG)

生成的ip地址

![](img/xp-2-ip.PNG)

- 配置intnet2中的Debian-victim-2

![](img/debian-victim-2-net.PNG)

生成的ip地址

![](img/debian-victim-2-ip.PNG)

- 配置攻击者kali-attacker

![](img/kali-attack-net.PNG)

ip地址

![](img/kali-attack-ip.PNG)

- 各个虚拟机对应的ip地址如下

| 虚拟机名称      | IP地址                      |
| --------------- | --------------------------- |
| Kali-attacker   | 10.0.2.6/24(NATNetwork)     |
| Kali-victim-1   | 172.16.111.142/24(intnet1)  |
| xp-victim-1     | 172.16.111.108/24(intnet1)  |
| xp-victim-2     | 172.16.222.112/24(intnet2)  |
| Debian-victim-2 | 172.16.222.121/24(intnet2)  |
| Debian-gateway  | 10.0.2.15/24(NATNetwork)    |
|                 | 192.168.25.11/24(Host-only) |
|                 | 172.16.111.1/24(intnet1)    |
|                 | 172.16.222.1/24(intnet2)    |



## 网络连通性测试

- 靶机可以直接访问攻击者主机

kali-victim-1 访问kali-attacker

![](img/kalivic1_ping_attack.PNG)

xp-victim-1访问kali-attacker

![](img/xpvic1_ping_attack.PNG)

Debian-victim-2访问kali-attacker

![](img/debvic2_ping_attack.PNG)

xp-victim-2访问kali-attacker

![](img/xpvic2_ping_attack.PNG)

- 攻击者主机无法直接访问靶机

![](img/attack_noping.PNG)

- 网关可以直接访问攻击者主机和靶机

![](img/gateway_ping.png)

- 靶机的所有对外上下行流量必须经过网关

在网关上安装`tcpdump`，并对对应网卡进行监控。在各个节点上访问互联网，观察捕获到的上下行的包。关闭网关，发现所有节点都无法访问互联网，由此说明，靶机的所有对外上下行流量必须经过网关。

```
apt istall tcpdump
/usr/sbin/tcpdump -i enp0s9 -n -w xxx.pcap
```

intnet1上靶机对外上下行流量经过网关

![](img/intnet1_pcap1.png)

![](img/intnet1_pcap2.png)

intnet2上靶机对外上下行流量经过网关

![](img/intnet2_pcap1.png)

![](img/intnet2_pcap2.png)

- 所有节点均可以访问互联网

xp-victim-1可访问互联网

![](img/xpvic1_ping_internet.PNG)

kali-victim-1可访问互联网

![](img/kalivic1_ping_internet.PNG)

xp-victim-2可访问互联网

![](img/xpvic2_ping_internet.PNG)

debian-victim-2可访问互联网

![](img/debvic2_ping_internet.PNG)

## 实验问题及解决方法

1. 执行`su`命令无法切换到root用户，显示`su: Authentication failure`

- 解决方法：`sudo su root`

## 参考资料

- [基于VirtualBox的网络攻防基础环境搭建](https://c4pr1c3.github.io/cuc-ns/chap0x01/exp.html)
- [老师提供的配置文件](https://gist.github.com/c4pr1c3/8d1a4525aa525fabcbfb25fad9718db1)
- [2019-NS-Public-YanhuiJessica](https://github.com/CUCCS/2019-NS-Public-YanhuiJessica/tree/ns0x01/ns-0x01)

