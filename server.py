import socket
import threading
import dhcppython
import ipaddress
import time
import json

ADDRESS = "127.0.0.1"
PORT = 68
bufferSize = 1024

f = open('config.json',)
DATA = json.load(f)
f.close()
LEASE_TIME = DATA["lease_time"]
times_left = {}

def get_client_name(pkt):
    name = pkt.options.by_code(12).data
    return name


def get_msg_type(pkt):
    data = pkt.options.by_code(53).data
    if data == b'\x01':
        return "DISCOVER"

    elif data == b'\x03':
        return "REQUEST"


def get_mac(pkt):
    return pkt.chaddr


def get_ip_pool(data):
    mode = data["pool_mode"]
    ip_pool = []
    if mode == "range":
        ip_range = data["range"]
        ip_from = ip_range["from"]
        ip_to = ip_range["to"]
        i = int(ip_from.split(".")[3])
        n = int(ip_to.split(".")[3])
        while i <= n:
            temp = ip_from.split(".")
            s = temp[0] + "." + temp[1] + "." + temp[2] + "." + str(i)
            ip_pool.append(s)
            print(s)
            i += 1

    elif mode == "subnet":
        ip_subnet = data["subnet"]
        print(ip_subnet)
        ip_block = ip_subnet["ip_block"]
        subnet = ip_subnet["subnet_mask"]
        s = ip_block + "/" + subnet
        ip_pool = list(ipaddress.ip_network(s, False).hosts())
        ip_pool = [str(i) for i in ip_pool]
        print(ip_pool)
    reserved = data["reservation_list"].values()
    pool = [i for i in ip_pool if i not in reserved]

    return pool


class DhcpClient:

    def __init__(self, xid, mac):
        self.mac = mac
        self.xid = xid
        self.reserved = False
        self.blocked = False
        self.leased_ip = None
        self.time_left = LEASE_TIME

    def is_reserved(self):
        return self.reserved

    def is_blocked(self):
        return self.blocked

    def expire_ip(self):
        self.leased_ip = None


def expire_ip(client, l, dict):
    ip = client.leased_ip
    client.leased_ip = None
    l.remove(client)
    del dict[client.xid]
    return ip


def expiring_ip(client):
    global clients_dict
    global acked_clients
    global offered_clients
    global ip_pool
    ip = client.leased_ip

    while times_left[client.mac]:
        times_left[client.mac] -= 1
        time.sleep(1)
    if client.mac not in reservation_list:
        ip_dict[ip] = False
    client.leased_ip = None
    try:
        del clients_dict[client.mac]
        # del clients_info[client.xid]
        del offered_clients[client.mac]
        del acked_clients[client.mac]
        del times_left[client.mac]
    except KeyError:
        print("client is already deleted.".upper())
    print("THE IP FOR CLIENT {} IS EXPIRED".format(client.mac))
    print("ddd", clients_dict)


if __name__ == '__main__':

    UDPServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    UDPServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # Bind to address and ip
    UDPServerSocket.bind((ADDRESS, PORT))
    ip_pool = get_ip_pool(DATA)
    ip_dict = {}
    for i in ip_pool:
        ip_dict[i] = False
    # print(ip_pool)
    reservation_list = DATA["reservation_list"]
    black_list = DATA["black_list"]
    print("DHCP server up and listening")
    clients_dict = {}
    offered_clients = {}
    acked_clients = {}
    info = {}

    while True:
        # print(clients_info)
        # print(clients_dict)
        # print(offered_clients)
        message, adr = UDPServerSocket.recvfrom(bufferSize)
        pkt = dhcppython.packet.DHCPPacket.from_bytes(message)
        msg_type = get_msg_type(pkt)
        xid = pkt.xid
        mac = pkt.chaddr
        if msg_type == 'DISCOVER':
            print("DISCOVERED A CLIENT, MAC: {}".format(mac))
            if mac not in clients_dict.keys() and mac not in black_list:
                client = DhcpClient(xid, mac)
                offered_clients[mac] = client

                if mac not in reservation_list.keys():
                    print("client does not have a reserved ip address".upper())
                    ip = ""
                    for i in ip_dict.keys():
                        if not ip_dict[i]:
                            ip = i
                    print(ip)
                    ip_dict[ip] = True
                else:
                    print("client has a reserved ip address".upper())
                    ip = reservation_list[mac]
                    print(ip)

                clients_dict[mac] = ip
                pkt = dhcppython.packet.DHCPPacket.Offer(mac, seconds=0, tx_id=xid,
                                                         yiaddr=ipaddress.IPv4Address(ip))
                UDPServerSocket.sendto(pkt.asbytes, adr)
                print("offer sent to client with mac:".upper(), mac)
        if msg_type == 'REQUEST':
            if mac not in acked_clients.keys() and mac not in black_list:
                ip = clients_dict[mac]
                c = offered_clients[mac]
                c.leased_ip = ip
                acked_clients[mac] = c
                times_left[mac] = 7 * LEASE_TIME
                info[mac] = {"MAC": mac, "IP": ip, "expiration time": c.time_left}
                x = threading.Thread(target=expiring_ip, args=(c,))
                x.start()

            if mac in acked_clients.keys():
                ip = clients_dict[mac]
                c = offered_clients[mac]
                c.leased_ip = ip
                # if LEASE_TIME > c.time_left > 1:
                #     c.time_left = LEASE_TIME
                x = threading.Thread(target=expiring_ip, args=(c,))
                x.start()


            pkt = dhcppython.packet.DHCPPacket.Ack(mac, seconds=0, tx_id=xid,
                                                   yiaddr=ipaddress.IPv4Address(ip))
            # time.sleep(10)
            print("ack sent to client with mac:".upper(), mac)
            print(pkt.options.by_code(53))
            UDPServerSocket.sendto(pkt.asbytes, adr)

        print(info)





