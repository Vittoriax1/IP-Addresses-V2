import ipaddress
import socket
import subprocess
import re
from ping3 import ping, verbose_ping
from ipwhois import IPWhois

def get_whois_info(ip_address):
    try:
        ip = IPWhois(ip_address)
        result = ip.lookup_rdap()
        # Extract relevant information from the result object
        # such as organization, country, etc.
        return result
    except Exception as e:
        print("Whois lookup failed:", str(e))
        return None

def perform_ping(ip_address):
    # Function to perform a ping test to the given IP address
    response = ping(ip_address)
    if response is not None:
        return f"Success! Average Round-Trip Time: {response * 1000:.2f} ms"
    else:
        return "Ping request timed out"

def traceroute(ip_address):
    try:
        result = subprocess.run(['tracert', '-d', '-w', '500', ip_address], capture_output=True)
        output = result.stdout.decode()
        if "Traceroute complete" in output:
            return True, output
        else:
            return False, output
    except subprocess.CalledProcessError as e:
        return False, str(e)

while True:
    # User input
    ip_address = input("Enter an IPv4 address (or 'exit' to quit): ")

    # Check if the user wants to exit
    if ip_address.lower() == 'exit':
        break

    try:
        # Parse the input IP address
        ip = ipaddress.IPv4Address(ip_address)

        # Determine the class of the IP address
        if ip.is_private:
            ip_class = "Private"
        else:
            first_octet = ip.packed[0]
            if first_octet < 128:
                ip_class = "Class A"
            elif first_octet < 192:
                ip_class = "Class B"
            elif first_octet < 224:
                ip_class = "Class C"
            elif first_octet < 240:
                ip_class = "Class D (Multicast)"
            else:
                ip_class = "Class E (Experimental)"

        # Calculate the network address and subnet mask
        network_address = ipaddress.IPv4Network(ip_address + '/24', strict=False)
        subnet_mask = network_address.netmask

        # Calculate the broadcast address
        broadcast_address = network_address.broadcast_address

        # Calculate the number of hosts
        num_hosts = network_address.num_addresses - 2

        # Perform Whois lookup
        whois_info = get_whois_info(ip_address)

        # Extract relevant information from the result
        if whois_info:
            country = whois_info.get('asn_country_code', 'Unknown')
        else:
            country = 'Unknown'

        # Perform ping test
        ping_result = perform_ping(ip_address)

        # Perform traceroute
        traceroute_success, traceroute_output = traceroute(ip_address)

        # Print the results
        print("IP Address:", ip_address)
        print("Class:", ip_class)
        print("Network Address:", network_address.network_address)
        print("Subnet Mask:", subnet_mask)
        print("Broadcast Address:", broadcast_address)
        print("Number of Hosts:", num_hosts)
        print("Owner:", whois_info['asn_description'] if whois_info else 'Unknown')
        print("Country:", country)
        print("Ping Test:", ping_result)
        print("Traceroute:")
        print(traceroute_output)
        print("----------------------")
    except ipaddress.AddressValueError:
        print("Invalid IP address. Please try again.")
