/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   listener.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/23 19:16:39 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 21:28:44 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

#define PCAP_FILTER\
	"src host %s and src port %i and dst host %s and dst port %i"

static void packet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,
		const u_char *packet)

{
	(void)pkthdr;
	(void)packet;
	chan ch = (chan)arg;
	ft_printf("received packet !!!\n");
	prettypacket((void*)packet, pkthdr->len);
	(void)ch;
	/* chs(ch, struct tcphdr, *(t_tcp_packet*)packet); */
}

coroutine void	listener_loop(chan ch, pcap_t *pcap_obj)
{
	ft_printf("listener loop\n");
	if (pcap_loop(pcap_obj, -1, packet_callback, (u_char*)ch) == -1)
	{
		ft_printf("pcap_loop fail\n");
		exit(EXIT_FAILURE);
	}
}

chan			nmap_listener(ipaddr dst, ipaddr src)
{
	char			errbuf[PCAP_ERRBUF_SIZE];
	pcap_t			*pcap_obj;
	bpf_u_int32		netp;
	bpf_u_int32		maskp;
	struct bpf_program fp;
	char	str[100];
	chan	pkts;

	pkts = chmake(struct tcphdr, 10);
	if (pcap_lookupnet("any", &netp, &maskp, errbuf) == -1)
	{
		exit(EXIT_FAILURE);
	}
	if (!(pcap_obj = pcap_open_live("any", BUFSIZ, 0, -1, errbuf)))
	{
		fprintf(stderr, "pcap_open_live: %s", errbuf);
		exit(EXIT_FAILURE);
	}
	if (!(sprintf(str, PCAP_FILTER, ipaddrstr(dst, str), ipport(dst),
									ipaddrstr(src, str), ipport(src))))
		exit(EXIT_FAILURE);
	if (pcap_compile(pcap_obj, &fp, str, 1, netp) == -1)
		exit(EXIT_FAILURE);
	if (pcap_setfilter(pcap_obj, &fp) == -1)
		exit(EXIT_FAILURE);
	go(listener_loop(pkts, pcap_obj));
	return (chdup(pkts));
}
