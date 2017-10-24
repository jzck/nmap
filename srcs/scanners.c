/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scanners.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/09 15:28:42 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 21:48:11 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

coroutine void	nmap_scan_tcp(chan results, t_job job)
{
	t_result	result;
	chan		pkts;
	ipaddr		src;
	int			sock;

	sock = socket(ipfamily(job.dest), SOCK_STREAM, IPPROTO_TCP);
	src = iplocal_randport(NULL, ipmode(job.dest), sock);
	pkts = nmap_listener(job.dest, src);

	result.dest = job.dest;
	ft_strcpy(result.scan, "TCP");

	struct tcphdr	pkt;
	result.status = CLOSED;

	tcp_hdrinit(&pkt);
	pkt.th_dport = htons(ipport(job.dest));
	pkt.th_sport = htons(ipport(src));
	/* pkt.th_flags = 0; */
	pkt.th_sum = cksum(&pkt, sizeof(pkt));

	if (sendto(sock, &pkt, sizeof(pkt), 0,
				(struct sockaddr*)&job.dest, sizeof(job.dest)) < 0)
	{
		perror("sendto");
		exit(1);
	}
	pkt = chr(pkts, struct tcphdr);

	chs(results, t_result, result);
	chclose(results);
	return ;
}
