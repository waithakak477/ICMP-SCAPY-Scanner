# ICMP-SCAPY-Scanner
 What is ICMP? (Internet Control Message Protocol)
ICMP (Internet Control Message Protocol) is a network layer protocol used to send error messages and operational information about network communication.

🔹 It is NOT used to send actual data but to diagnose network issues.
🔹 ICMP is most commonly associated with ping commands for checking network connectivity.

Scapy: Used to create and send network packets.

ipaddress: Helps handle IP addresses and network ranges.

Ping Sweep: Sends ICMP ping requests to every IP in the range to check which hosts are online.

ICMP Types:

Type 0: Echo reply (host is online).

Other types: Indicate potential filtering or firewalls.

User Input: The script asks for a network range (e.g., 192.168.1.0/24) and scans it.

How It Works:
The script sends a ping (ICMP request) to every IP in the specified range.

If a host responds, it’s marked as online.

If no response is received, the host is considered offline or unreachable.

Results are displayed in a user-friendly format
