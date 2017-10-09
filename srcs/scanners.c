/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scanners.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/09 15:28:42 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/09 16:14:35 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

coroutine void	nmap_scan_tcp(int ch, t_data *data, t_target target)
{
	int				listen;
	t_scan_result	res;
	t_tcp_packet	pkt;

	listen = capture_chan(target);

	iphdr_init(&pkt.iph);

	pkt.iph.protocol = IPPROTO_TCP;
	pkt.iph.saddr = *(uint32_t*)&((struct sockaddr_in*)&data->out_sa[target.scan])->sin_addr;
	pkt.iph.daddr = *(uint32_t*)&((struct sockaddr_in*)target.host->addr)->sin_addr;
	pkt.iph.tot_len = htons(sizeof(t_tcp_packet));

	tcphdr_init(&pkt.tcph);
	packet.tcph.dest = htons(target.port);
	packet.tcph.check = cksum(&packet, sizeof(t_tcp_packet));

	if (sendto(sock, &packet, sizeof(packet), 0,
				host->addr, host->addrlen) < 0)
	{
		perror("sendto");
		exit(1);
	}
	/* chrecv(channel, &buf, sizeof()) */
	hexdump(&packet, sizeof(packet));


	chsend(ch, res, sizeof(res), -1);
	printf("result sent\n");
	hclose(ch);
}
