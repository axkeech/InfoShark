import pyshark
import socket
import geoip2.database
import whois
from collections import Counter
import sys

cap = pyshark.FileCapture(sys.argv[1])

ipPortsTracker = {}
    
def get_service(port):
    try:
        # get the service name of the port using getservbyport()
        service = socket.getservbyport(int(port))
    except OSError:
        # if port number isn't found, return "unknown"
        service = "unknown"
    return service

def ip_whois_lookup(ip_address):
    try:
        w = whois.whois(ip_address)
        print(f"Domain: ",w.domain_name)
    except Exception as e:
        print("Error: {}".format(str(e)))

def ip_address_location(ip_address):
    # get hostname of ip address
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        hostname = "unknown"

    reader = geoip2.database.Reader('/usr/share/king-phisher/data/server/king_phisher/GeoLite2-City.mmdb')
    try:
        response = reader.city(ip_address)
        city = response.city.name
        region = response.subdivisions.most_specific.name
        country = response.country.name
        latitude = response.location.latitude
        longitude = response.location.longitude
        print(f"Hostname: {hostname}")
        print(f"  City: {city}")
        print(f"  Region: {region}")
        print(f"  Country: {country}")
        print(f"  Latitude: {latitude}")
        print(f"  Longitude: {longitude}")
    except geoip2.errors.AddressNotFoundError:
        print("The IP address was not found in the GeoIP database.")

for packet in cap:

    if "IP Layer" in str(packet.layers):
        
        if "TCP" in str(packet.transport_layer):

            srcIp = str(packet.ip.src)
            srcmac = str(packet.eth.src)
            dstIP = str(packet.ip.dst)
            dstmac = str(packet.eth.dst)
            srcPort = str(packet.tcp.srcport)
            dstPort = str(packet.tcp.dstport)

            if srcIp not in ipPortsTracker:
                ipPortsTracker[srcIp] = {'srcmac': srcmac, 'srcport': Counter(), 'dstport': Counter(), 'dstip': Counter()}
            ipPortsTracker[srcIp]['srcport'][srcPort] += 1
            ipPortsTracker[srcIp]['dstport'][dstPort] += 1
            ipPortsTracker[srcIp]['dstip'][dstIP] += 1
        
        if "UDP" in str(packet.transport_layer):

            srcIp = str(packet.ip.src)
            srcmac = str(packet.eth.src)
            dstIP = str(packet.ip.dst)
            dstmac = str(packet.eth.dst)
            srcPort = str(packet.udp.srcport)
            dstPort = str(packet.udp.dstport)

            if srcIp not in ipPortsTracker:
                ipPortsTracker[srcIp] = {'srcmac': srcmac, 'srcport': Counter(), 'dstport': Counter(), 'dstip': Counter()}
            ipPortsTracker[srcIp]['srcport'][srcPort] += 1
            ipPortsTracker[srcIp]['dstport'][dstPort] += 1
            ipPortsTracker[srcIp]['dstip'][dstIP] += 1
        



for ip in ipPortsTracker:
    print(f"==============================================")
    print(f"Source IP: {ip}")
    print(f"Source MAC: {ipPortsTracker[ip]['srcmac']}")
    ip_whois_lookup(ip)
    ip_address_location(ip)
    print("Top 5 Source Ports:")
    for port, count in ipPortsTracker[ip]['srcport'].most_common(5):
        print(f"  Port {port} - Service {get_service(port)}: {count} packets")
    print("Top 5 Destination Ports:")
    for port, count in ipPortsTracker[ip]['dstport'].most_common(5):
        print(f"  Port {port} - Service {get_service(port)}: {count} packets")
    print("Top 5 Destination IPs:")
    for port, count in ipPortsTracker[ip]['dstip'].most_common(5):
        print(f"  IP {port}: {count} packets")
    print(f"==============================================")
    print()
