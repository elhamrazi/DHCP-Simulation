import socket
import threading
import random
import dhcppython
import tqdm
import time

BACKOFF_CUTOFF = 120
INITIAL_INTERVAL = 10
ACK_TIMEOUT = 40
PORT = 67
ADDRESS = socket.gethostbyname(socket.gethostname())


class Client:

    def __init__(self, sock, xid, mac):
        self.sock = sock
        self.xid = xid
        self.mac = mac
        self.ip = None

    def create_req(self, mode):
        if mode == 'DISCOVER':
            pkt = dhcppython.packet.DHCPPacket.Discover(self.mac)

        else:
            pkt = dhcppython.packet.DHCPPacket.Request(self.mac, seconds=0, tx_id=self.xid)

        return pkt

    def get_msg_type(self, pkt):
        data = pkt.options.by_code(53).data
        if data == b'\x02':
            return "OFFER"

        elif data == b'\x05':
            return "ACK"

    def expire_ip(self):
        self.ip = None

    def send_dhcp_req(self):
        old_timeout = INITIAL_INTERVAL
        timeout = INITIAL_INTERVAL
        while True:
            # send discover
            if self.ip is None:
                try:
                    pkt = self.create_req('DISCOVER')
                    self.sock.sendto(pkt.asbytes, ('<broadcast>', 68))
                    self.sock.settimeout(timeout)
                    data, adr = self.sock.recvfrom(1024)
                    dhcp_pkt = dhcppython.packet.DHCPPacket.from_bytes(data)
                    print("THE OFFERED IP ADDRESS FROM DHCP SERVER: ", dhcp_pkt.yiaddr)
                    req = self.create_req("REQUEST")
                    self.sock.sendto(req.asbytes, adr)
                    print("REQUEST SENT TO SERVER")
                    old_timeout = self.sock.gettimeout()
                    self.sock.settimeout(ACK_TIMEOUT)
                    data, adr = self.sock.recvfrom(1024)
                    pkt = dhcppython.packet.DHCPPacket.from_bytes(data)
                    print(pkt.options.by_code(53))
                    print(old_timeout)
                    self.sock.settimeout(ACK_TIMEOUT)
                    res = self.get_msg_type(pkt)
                    print(res)
                    if res == 'ACK':
                        print("ACK RECEIVED")
                        self.ip = pkt.yiaddr
                        print("LEASED IP:", self.ip)
                        t = threading.Timer(60, self.expire_ip)
                        t.start()

                except socket.timeout:
                    print("SENDING DISCOVER AGAIN")
                    # pkt = self.create_req('DISCOVER')
                    # self.sock.sendto(pkt.asbytes, ('<broadcast>', 68))
                    timeout = old_timeout
                    timeout += random.random() * 2
                    old_timeout = timeout
                    print(timeout)
                    if timeout > BACKOFF_CUTOFF:
                        timeout = INITIAL_INTERVAL
                        old_timeout = INITIAL_INTERVAL
                    self.sock.settimeout(timeout)
                    print("TIME OUT", self.sock.gettimeout())
            else:
                print("CLIENT IS ASSIGNED TO AN IP")
                for q in tqdm.tqdm(range(0, 60), desc="TIME LEFT"):
                    time.sleep(1)


if __name__ == '__main__':
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client_sock.bind(("127.0.0.1", 65418))

    mac = "48:4F:6A:1E:59:3D"
    xid = random.randint(0, 2**32)
    client = Client(client_sock, xid, mac)
    client.send_dhcp_req()









