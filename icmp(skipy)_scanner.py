from scapy.all import IP, ICMP, sr1, ARP, Ether, srp
import socket
import ipaddress

def get_device_name(ip):
    """Resolve IP address to hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def get_manufacturer(mac):
    """Get manufacturer name from MAC address using Scapy's manuf database."""
    from scapy.layers.l2 import manuf
    try:
        return manuf.manufdb._get_manuf(mac)
    except Exception:
        return "Unknown"

def get_mac_address(ip):
    """Send an ARP request to retrieve the MAC address."""
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request
    result = srp(packet, timeout=2, verbose=False)[0]
    
    if result:
        return result[0][1].hwsrc  # Return the MAC address from the response
    return "Unknown"

def ping_sweep(network):
    """Scans a network range using ICMP ping requests and retrieves additional info."""
    live_hosts = []
    
    print(f"\n🔍 Scanning network: {network}...\n")
    
    for ip in ipaddress.IPv4Network(network, strict=False):
        ip = str(ip)
        # Send ICMP ping request
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=1, verbose=False)
        
        if response is None:
            print(f"❌ {ip} is not responding (Possible firewall or offline).")
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            if icmp_type == 0:  # Echo reply
                # Get MAC address using ARP request
                mac = get_mac_address(ip)
                # Get device name
                device_name = get_device_name(ip)
                # Get manufacturer
                manufacturer = get_manufacturer(mac)
                # Print results
                print(f"✅ {ip} is ONLINE (Ping reply received).")
                print(f"   - Device Name: {device_name}")
                print(f"   - MAC Address: {mac}")
                print(f"   - Manufacturer: {manufacturer}")
                live_hosts.append((ip, device_name, mac, manufacturer))
            else:
                print(f"⚠️ {ip} responded with ICMP Type {icmp_type} (Potential firewall or filtering).")
    
    print("\n🔎 Scan Complete!")
    if live_hosts:
        print("✅ Live hosts detected:")
        for host in live_hosts:
            print(f"   - IP: {host[0]}, Name: {host[1]}, MAC: {host[2]}, Manufacturer: {host[3]}")
    else:
        print("❌ No live hosts found.")

if __name__ == "__main__":
     
    # Define the network range to scan (e.g., 192.168.0.0/24)
    network_range = "192.168.0.100/28"  # This covers 192.168.0.100 to 192.168.0.115
    ping_sweep(network_range)