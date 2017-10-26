/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scanners.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/09 15:28:42 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/26 17:37:43 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

coroutine void	nmap_scan_tcp(chan results, t_job job)
{
	t_result	result;
	ipaddr		src;
	int			sock;

	sock = socket(ipfamily(job.dest), SOCK_STREAM, IPPROTO_TCP);
	src = iplocal_randport(NULL, ipmode(job.dest), sock);

	pcap_t *handle = nmap_capture(job.dest, src);
	/* chan		pkts; */
	/* pkts = nmap_listener(job.dest, src); */
	/* (void)pkts; */
	/* DG("after listener"); */

	result.dest = job.dest;
	ft_strcpy(result.scan, "TCP");

	struct tcphdr	pkt;
	result.status = CLOSED;

	tcp_hdrinit(&pkt);
	pkt.th_dport = htons(ipport(job.dest));
	pkt.th_sport = htons(ipport(src));
	pkt.th_flags = 0;
	pkt.th_sum = cksum(&pkt, sizeof(pkt));

	tcp_print((char *)&pkt, sizeof(pkt));

	// REQ
	DG("check");
	fdwait(sock, FDW_IN, now() + 1000);
	if (sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr*)&job.dest, sizeof(job.dest)) < 0)
	{
		DG("check 1");
		perror("sendto");
	}
	DG("check 2");

	// RESP
	struct pcap_pkthdr	pkthdr;
	const u_char		*resp;
	resp = pcap_next(handle, &pkthdr);
	tcp_print((char *)resp, pkthdr.len);

	chs(results, t_result, result);
	chclose(results);
	return ;

}
