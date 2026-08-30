#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <arpa/inet.h> 
#include <net/ethernet.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>	
#include <netinet/ip.h>	

struct network_flow{
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int protocol;
	bool retransmitted;
	struct network_flow* next;
};

int flows = 0;
int flowsTCP = 0;
int flowsUDP = 0;
int packets = 0;
int packetsTCP = 0;
int packetsUDP = 0;
int bytesTCP = 0;
int bytesUDP = 0;
pcap_t *handle;
FILE *log_file;
char *mode;
struct network_flow *network_flow_head = NULL;

//Help message
void print_help(){
	printf(
		   "Parameter options:\n"
		   "-i Select the network interface name (e.g. eth0)\n"
		   "-r Packet capture file name (e.g. test.pcap)\n"
		   "-f Filter expression in string format (e.g. port 8080)\n"
		   "-h Help message, which shows the usage of each parameter\n"
		   );
}

//Statistics
void print_info(){	
	printf(
		   "\nTotal number of network flows captured: %d\n"
		   "Number of TCP network flows captured: %d\n"
		   "Number of UDP network flows captured: %d\n"
		   "Total number of packets received: %d\n"
		   "Total number of TCP packets received: %d\n"
		   "Total number of UDP packets received: %d\n"
		   "Total bytes of TCP packets received: %d\n"
		   "Total bytes of UDP packets received: %d\n",
		   flows, flowsTCP, flowsUDP, packets, packetsTCP, packetsUDP, bytesTCP, bytesUDP
		   );
}

//Check if network flow already exists
bool flow_exists(struct network_flow *flow, char *src_ip, char *dst_ip, int protocol, unsigned int src_port, unsigned int dst_port){
	if(flow == NULL)
		return false;

	struct network_flow *temp = flow;
    while(temp != NULL){
        if((strcmp(temp->src_ip, src_ip) == 0) && (strcmp(temp->dst_ip, dst_ip) == 0) && temp->protocol == protocol && temp->src_port == src_port && temp->dst_port == dst_port)
            return true;

        temp = temp->next;
    }
	return false;
}

//Insert a new network flow at the end of the list
void insert_new_flow(struct network_flow *flow, char *src_ip, char *dst_ip, int protocol, unsigned int src_port, unsigned int dst_port){
	struct network_flow *new_flow = (struct network_flow *)malloc(sizeof(struct network_flow));
	struct network_flow *temp = flow;
	struct pcap_stat stats;

	//First network flow of the list
	if(flow == NULL){
		memcpy(new_flow->src_ip, src_ip, INET_ADDRSTRLEN);
		memcpy(new_flow->dst_ip, dst_ip, INET_ADDRSTRLEN);
		new_flow->protocol = protocol;
		new_flow->src_port = src_port;
		new_flow->dst_port = dst_port;
		new_flow->next = NULL;
		network_flow_head = new_flow;

		//Update statistics
		flows++;
		if(new_flow->protocol == IPPROTO_TCP){
			if (pcap_stats(handle, &stats) < 0) {
    			fprintf(stderr, "Couldn't get statistics: %s\n", pcap_geterr(handle));
				flowsTCP++;
    			return;
  			}
			if (stats.ps_drop > 0) {
    			printf("Retransmitted.\n");
				new_flow->retransmitted = true;
  			}
			else 
				new_flow->retransmitted = false;
			
			flowsTCP++;
		}
		else if (new_flow->protocol == IPPROTO_UDP){
			flowsUDP++;
			new_flow->retransmitted = false;
		}
		return;
	}

	flows++;
	while(temp->next != NULL)
		temp = temp->next;

	temp->next = new_flow;
	memcpy(new_flow->src_ip, src_ip, INET_ADDRSTRLEN);
	memcpy(new_flow->dst_ip, dst_ip, INET_ADDRSTRLEN);
	new_flow->protocol = protocol;
	new_flow->src_port = src_port;
	new_flow->dst_port = dst_port;
	new_flow->next = NULL;

	if(new_flow->protocol == IPPROTO_TCP){
		if (pcap_stats(handle, &stats) < 0) {
    		fprintf(stderr, "Couldn't get statistics: %s\n", pcap_geterr(handle));
			flowsTCP++;
    		return;
  		}
		if (stats.ps_drop > 0) {
    		printf("Retransmitted.\n");
			new_flow->retransmitted = true;
  		}
		else new_flow->retransmitted = false;
			
		flowsTCP++;
	}
	else if (new_flow->protocol == IPPROTO_UDP){
		flowsUDP++;
		new_flow->retransmitted = false;
	}
}

//TCP packet handler
void tcp_handler(const u_char *packet, int size){
	packetsTCP++;
	char src_ip_addr[INET_ADDRSTRLEN];
	char dst_ip_addr[INET_ADDRSTRLEN];
	const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
	struct ether_header *ethernet_header = (struct ether_header*)packet;

	if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP && ntohs(ethernet_header->ether_type) != ETHERTYPE_IPV6) {
		printf("Can't support protocols that aren't IPv4 or IPv6.\n");
		return;
	}
	
	inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_addr, INET_ADDRSTRLEN);
	
	struct tcphdr *tcp_header =(struct tcphdr*)(packet + ip_header->ip_hl*4 + sizeof(struct ethhdr));
	int payload_length = size - (tcp_header->doff*4 + tcp_header->doff*4);
	u_int *payload = (u_int *)(packet + sizeof(struct ether_header) + ip_header->ip_hl*4 + tcp_header->doff*4);
	bytesTCP += size;
	
	if(!flow_exists(network_flow_head, src_ip_addr, dst_ip_addr, (unsigned int)ip_header->ip_p, ntohs(tcp_header->source), ntohs(tcp_header->dest)))
		insert_new_flow(network_flow_head,src_ip_addr,dst_ip_addr,(unsigned int)ip_header->ip_p,ntohs(tcp_header->source),ntohs(tcp_header->dest));
	
	printf(
		   "Source IP: %s | Destination IP: %s | Source Port: %u | "
		   "Destination Port: %u | Protocol: TCP | Header Length: %d | "
		   "Payload Length: %d | Payload memory address: %p\n", 
		   src_ip_addr, dst_ip_addr, ntohs(tcp_header->source), ntohs(tcp_header->dest), 
		   (unsigned int)tcp_header->doff*4, payload_length, (void *)payload
		   );

	if(mode == "online"){
		char line[512];
		sprintf(
				line,"Source IP: %s | Destination IP: %s | Source Port: %u | "
				"Destination Port: %u | Protocol: TCP | Header Length: %d | "
				"Payload Length: %d | Payload memory address: %p\n", 
				src_ip_addr, dst_ip_addr, ntohs(tcp_header->source), ntohs(tcp_header->dest), 
				(unsigned int)tcp_header->doff*4, payload_length, (void *)payload
				);
		fprintf(log_file, line, strlen(line));
	}

	return;
}

//UDP packet handler
void udp_handler(const u_char * packet, int size){
	packetsUDP++;
	char src_ip_addr[INET_ADDRSTRLEN];
	char dst_ip_addr[INET_ADDRSTRLEN];
	const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr) );
	struct ether_header *ethernet_header = (struct ether_header*)packet;

	if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP && ntohs(ethernet_header->ether_type) != ETHERTYPE_IPV6) {
		printf("Can't support protocols that aren't IPv4 or IPv6.\n");
		return;
	}
	
	inet_ntop(AF_INET, &(ip_header->ip_src), src_ip_addr, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip_addr, INET_ADDRSTRLEN);
	
	struct udphdr *udp_header = (struct udphdr*)(packet + ip_header->ip_hl*4 + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + ip_header->ip_hl*4 +sizeof(udp_header);
	int payload_length = size - header_size;
	u_int *payload = (u_int *)(packet + sizeof(struct ether_header) + ip_header->ip_hl*4 + udp_header->len);
	bytesUDP += size;

	if(!flow_exists(network_flow_head, src_ip_addr,dst_ip_addr, (unsigned int)ip_header->ip_p, ntohs(udp_header->source), ntohs(udp_header->dest)))
		insert_new_flow(network_flow_head, src_ip_addr, dst_ip_addr,(unsigned int)ip_header->ip_p,ntohs(udp_header->source),ntohs(udp_header->dest));
	
	printf(
		   "Source IP: %s | Destination IP: %s | Source Port: %u | "
		   "Destination Port: %u | Protocol: UDP | Header Length: %d | "
		   "Payload Length: %d | Payload memory address: %p\n", 
		   src_ip_addr, dst_ip_addr, ntohs(udp_header->source), ntohs(udp_header->dest), 
		   (unsigned int)udp_header->len, payload_length, (void *)payload
		   );
	
	if(mode == "online"){
		char line[512];
		sprintf(
				line,"Source IP: %s | Destination IP: %s | Source Port: %u | "
				"Destination Port: %u | Protocol: UDP | Header Length: %d | "
				"Payload Length: %d | Payload memory address: %p\n", 
				src_ip_addr, dst_ip_addr, ntohs(udp_header->source), ntohs(udp_header->dest), 
				(unsigned int)udp_header->len, payload_length, (void *)payload
				);
		fprintf(log_file, line, strlen(line));
	}
	return;
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
	int size = header->len;
	const struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));
	packets++;

	if(ip_header->ip_p == IPPROTO_TCP)
		tcp_handler(packet, size);
	else if(ip_header->ip_p == IPPROTO_UDP)
		udp_handler(packet, size);
}

void exit_loop(){
	pcap_breakloop(handle);
	pcap_close(handle);
	fclose(log_file);
}

void online_handler(char *dev, char *filter){
    char error_buffer[PCAP_ERRBUF_SIZE];	 
    int timeout = 5000;				 
	struct bpf_program bfp;           
	bpf_u_int32 mask;                
    bpf_u_int32 net;                 
	log_file = fopen("log.txt", "w");

    if (dev == NULL) {
        printf("Couldn't find device: %s\n", error_buffer);
		exit(EXIT_FAILURE);
	}
	printf("Device: %s\n", dev);
    if (pcap_lookupnet(dev, &net, &mask, error_buffer) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, error_buffer);
        net = 0;
        mask = 0;
    }

	mode = "online";
    handle = pcap_open_live(dev, BUFSIZ, 0, timeout, error_buffer);   
    if(handle == NULL){
        printf("Couldn't open device: %s\n", error_buffer);
		return ;
	}

	if(filter != NULL){
        if (pcap_compile(handle, &bfp, filter, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
        if (pcap_setfilter(handle, &bfp) == -1) {
            fprintf(stderr, "Couldn't apply filter %s: %s\n", filter, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
	}
	signal(SIGINT, exit_loop);
	pcap_loop(handle, timeout, packet_handler, NULL);		
	print_info();
	return;
}

void offline_handler(char *file_name){
	char error_buffer[PCAP_ERRBUF_SIZE];	
	mode = "offline";
	handle = pcap_open_offline(file_name, error_buffer);

	if(handle != NULL){
		pcap_loop(handle, -1, packet_handler ,NULL);
		print_info();
	}
	else 
		printf("Couldn't open file.\n");
	return;
}

int main(int argc, char* argv[]){
    int ch;
	char *device = NULL;
	char *filter = NULL;

    while ((ch = getopt(argc, argv, "i:f:r:h")) != -1) {
		switch(ch) {
		case 'i':
			device = strdup(optarg);
			break;
		case 'f':
			filter = strdup(optarg);
			break;
		case 'r':
			offline_handler(optarg);
			exit(0);
			break;
		case 'h':
			print_help();
			exit(1);
		default:
            printf("Please insert the correct arguements.\n");
			exit(2);
		}		
	} 

	online_handler(device, filter);

    return 0;
}