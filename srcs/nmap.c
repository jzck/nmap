#include "nmap.h"

unsigned short cksum(void *b, int len)
{
	unsigned short	*buf = b;
	unsigned int	sum=0;

	for (sum = 0; len > 1; len -= 2)
		sum += *((unsigned short*)buf++);
	if (len == 1)
		sum += *(unsigned char*)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	return (~(sum + (sum >> 16)));
}

coroutine void	nmap_scan_port(t_data *data, struct iphdr *iph, int port)
{
	int				channel;
	t_tcp_packet	packet;

	channel = data.channels[port];

	packet.iph = *iph;
	tcphdr_init(&packet.tcph);
	packet.tcph.dest = htons(port);
	packet.tcph.source = htons(data->src_port);
	/* packet.tcph.syn = 1; */
	packet.tcph.check = cksum(&packet, sizeof(t_tcp_packet));

	if ((host.sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		perror("server: socket");

	int val = 1;
	if (setsockopt(host.sock_tcp, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) == -1)
		return (1);


	if (sendto(host->sock_tcp, &packet, sizeof(packet), 0, host->addr, host->addrlen) < 0)
	{
		perror("sendto");
		exit(1);
	}
	/* chrecv(channel, &buf, sizeof()) */
	printf("packet sent\n");
	hexdump(&packet, sizeof(packet));
}

void	nmap(t_data *data)
{
	t_list	*list;
	t_host	*host;
	struct iphdr	iph;

	iphdr_init(&iph);
	iph.protocol = IPPROTO_TCP;
	iph.daddr = *(uint32_t*)&((struct sockaddr_in*)host->addr)->sin_addr;
	iph.saddr = *(uint32_t*)&((struct sockaddr_in*)&data->source_addr)->sin_addr;
	iph.tot_len = htons(sizeof(t_tcp_packet));

	for (t_list *list = data->host; list != NULL; list = list->next)
	{
		t_host *host = list->content;
		printf("scanning %s...\n", host->dn);
		for (port = 1; port < USHRT_MAX; port++;)
		{
			if (data.ports[port])
				go(nmap_scan_port(data, iph, port));
		}
	}
}
