# IP-Addresses-V2
This is the second version of the IP lookup tool. It had additional functions.

This script with accept user input of an IPv4 address. 
It will determine the class type of the IP address, the network portion of the address, 
the subnet mask, the broadcast address, and the number of hosts.

The script will then utilize ipwhois to find whois information of the IP.
Currently, it will output the company name and the country, if that information is made available.

It will test the ping latency rate, and output it.

The script will also perform a traceroute, and show the path, times in ms and the IP addresses of the 
stops between the user and the target IP address.
