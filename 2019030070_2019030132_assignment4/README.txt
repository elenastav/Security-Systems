MAKEFILE:
To compile all programs: make all
To remove the generated files: make clean

EXAMPLES TO RUN:
sudo ./pcap_ex -i enp0s3
sudo ./pcap_ex -i enp0s3 -f "port 8080"
sudo ./pcap_ex -r test_pcap_5mins.pcap

ASSIGNMENT DESCRIPTION:
The purpose of this assignment is to create a Network traffic monitoring program using the Packet Capture library. Specifically, the program should be able to capture live from a network interface and read a pcap file offline. The online outputs are written in a log.txt file and the offline outputs are printed in the terminal. 

Can you tell if an incoming TCP packet is a retransmission? If yes, how? If not, why?
A TCP retransmission happens when the sender never receives an acknowledgement (ACK) for a segment of data that he sent. So, to make sure that the segment gets to the receiver, the sender retransmits it. We can detect retransmissions by looking at the sequence number of that TCP segment. The sequence number is a 32-bit field in the header that works as an identifier for the first byte position in a segment in a data stream. So, if a segment is a retransmission, it will have the same sequence number with the previous segment that was sent. 

Can you tell if an incoming UDP packet is a retransmission? If yes, how? If not, why?
When a UDP packet is lost, no retransmission happens and the data loss is inevitable. So, unlike TCP, UDP packets can't be retransmissions.


