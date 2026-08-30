Assignment 6 

Kleinta Giaoupi 2019030132 & Elena Stavropoulou 2019030070


->Report any icmp connection attempt in test_pcap_5mins.pcap

Rule:
alert icmp any any -> any any (msg:"ICMP Connection Attempt"; sid:100001;)

This is an alert rule that triggers an alert for any ICMP traffic from any source to any destination, indicating a generic "ICMP Connection Attempt." The rule has a unique identifier (SID) of 100001.

Output:
01/25-20:54:19.749652  [**] [1:100001:0] ICMP Connection Attempt [**] [Priority: 0] {ICMP} 10.0.2.2 -> 10.0.2.15

There seem to be various ICMP connection attempts from IP 10.0.2.2 to 10.0.2.15.

---------------------------------------------------------------------------------------------------------

->Find all packets which contain “hello” string in test_pcap_5mins.pcap.

Rule: 
alert ip any any -> any any (content:"hello"; msg:"Packet contains 'hello'"; sid:100002;)

This rule triggers an alert for any IP packet, regardless of source and destination, that contains the string "hello" in its payload. The associated message is "Packet contains 'hello'", and the rule ID is 100002.

Output:
01/25-20:57:01.233990  [**] [1:100002:0] Packet contains 'hello' [**] [Priority: 0] {TCP} 70.37.129.34:5480 -> 10.0.2.15:2553
01/25-20:55:11.233990  [**] [1:100002:0] Packet contains 'hello' [**] [Priority: 0] {TCP} 70.37.129.34:80 -> 10.0.2.15:2553

Two TCP packets were flagged by Snort IDS, originating from IP 70.37.129.34 on non-standard ports 80 and 5480, both containing the string 'hello' in their payload. They were destined for local IP 10.0.2.15 on port 2553.

---------------------------------------------------------------------------------------------------------

->Report all traffic between non root ports (port number > 1024).

Rule:
alert tcp any any -> any !1:1024 (msg:"Non-root Port Traffic"; sid:100003;)

This rule generates an alert for TCP traffic from any source port to any destination port, excluding the well-known ports (1-1024), and the associated alert message is "Non-root Port Traffic."

Output:
01/25-20:57:18.019364  [**] [1:100003:0] Non-root Port Traffic [**] [Priority: 0] {TCP} 204.14.234.101:443 -> 192.168.3.131:57231

The rule is triggered multiple times with variations in source and destination ports and IPs. The alert message indicates "Non-root Port Traffic," and the priority is 0.

---------------------------------------------------------------------------------------------------------

->Create a rule that will detect ssh brute force attacks in sshguess.pcap file. A brute force attempt can be realized as 10 attempts within 10 minutes.

Rule:
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; detection_filter:track by_src, count 10, seconds 600; sid:100004;)

This alert rule (sid:100004) triggers on TCP traffic from any source IP and port to any destination IP on port 22 (SSH). The message "SSH Brute Force Attempt" is logged when 10 or more occurrences from the same source IP are detected within a 10-minute timeframe.

Output:
03/30-16:45:55.571689  [**] [1:100004:0] SSH Brute Force Attempt [**] [Priority: 0] {TCP} 192.168.56.1:55480 -> 192.168.56.103:22

The output suggests that the source IP 192.168.56.1 is repeatedly attempting to establish a connection to the SSH port (22) on the destination IP 192.168.56.103. The alerts are triggered for each attempt, indicating that the rule for detecting SSH brute force attempts is working as expected.

---------------------------------------------------------------------------------------------------------

->Setup the community rules (run snort with associated snort.conf) and report any clear indicator of malicious traffic in test_pcap_5mins.pcap. Some community rules clearly state the exploit detected.

After downloading the latest version of the community rules from the Snort website, we included them in the configuration file and the output indicated potentially malicious traffic such as: 

-Events with high priority(1) that need to be attended immediately:
MSN Chat Activity:
Signature [1:1990:1] CHAT MSN user search and [1:540:11] CHAT MSN message
Classification: Potential Corporate Privacy Violation

-Events with medium priority(2) of moderate severity:
IIS Access with %2E-asp:
Signature: [1:972:8] WEB-IIS %2E-asp access
Classification: Access to a potentially vulnerable web application

SNMP Public Access Attempts:
Signature: [1:1411:10] SNMP public access udp and [1:1417:9] SNMP request udp
Classification: Attempted Information Leak

-Events with low priority(3) which are less severe or informational:
Web Bug Attempts:
Signature: [1:2925:3] INFO web bug 0x0 gif attempt
Classification: Misc activity

UPnP Service Discover Attempts:
Signature: [1:1917:6] SCAN UPnP service discover attempt
Classification: Detection of a Network Scan

Web Bug Attempts to Different IPs:
Signature: [1:2925:3] INFO web bug 0x0 gif attempt
Classification: Misc activity

ICMP Destination Unreachable and L3retriever Ping:
Signature: [1:485:4] ICMP Destination Unreachable Communication Administratively Prohibited and [1:466:4] ICMP L3retriever Ping
Classification: Misc activity and Attempted Information Leak

