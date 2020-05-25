import scapy.all as scapy


# Create an arp request directed to broadcast MAC asking for IP
# Use ARP to ask who has target IP
# Set destination MAC to broadcast MAC

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Sending and receiving packets

    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)

    # parse the response

    print("IP\t\t\tMAC Address\n----------------------------------------------")
    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


# Printing the result

def print_result(results_list):
    print("IP\t\t\tMAC Address")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan("10.0.2.1/24")
print_result((scan_result))
