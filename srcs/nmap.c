/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/22 14:10:24 by jhalford          #+#    #+#             */
/*   Updated: 2017/04/23 18:18:41 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

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

int		nmap_scan_tcp(t_data *data, struct iphdr *iph, t_host *host, int port)
{
	t_tcp_packet	packet;

	packet.iph = *iph;

	tcphdr_init(&packet.tcph);
	packet.tcph.dest = htons(port);
	packet.tcph.source = htons(data->src_port);
	packet.tcph.syn = 1;
	packet.tcph.check = cksum(&packet, sizeof(t_tcp_packet));
	if (sendto(host->sock_tcp, &packet, sizeof(packet), 0, host->addr, host->addrlen) < 0)
	{
		perror("sendto");
		exit(1);
	}
	printf("packet sent\n");
	sleep(2);
	return (0);
}

/* int		nmap_scan(char *host, int port, int scan) */
/* { */
/* 	(void)scan; */
/* 	nmap_scan_syn(sockfd, servinfo); */
/* 	return (0); */
/* } */

void	nmap(t_data *data)
{
	t_list	*list;
	t_host	*host;
	struct iphdr	iph;

	list = data->host;
	if (!list)
		return ;
	for (host = list->content; list != NULL; list = list->next )
	{
		printf("scanning %s...\n", host->dn);

		iphdr_init(&iph);
		iph.protocol = IPPROTO_TCP;
		iph.daddr = *(int32_t*)host->addr;
		iph.tot_len = sizeof(t_tcp_packet);

		nmap_scan_tcp(data, &iph, host, 80);
		break ;
	}
}

