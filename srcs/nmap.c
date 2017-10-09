/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/08 19:10:07 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/09 17:12:31 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

t_scanner	g_scanners[SCAN_MAX]
{
	scan_tcp,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	/* scan_syn, */
	/* scan_ack, */
	/* scan_fin, */
	/* scan_xmas, */
	/* scan_udp, */
}

coroutine void	nmap_scan_port(int ch, t_data *data, t_target target)
{
	int			fan_in;
	int			fan_in_local;
	int			scan;

	fan_in = chmake(sizeof(t_scan_result));
	while (scan = bitfield_lsb(data.scans, USHRT_MAX + 1))
	{
		data.scans &= ~scan;
		fan_in_local = hdup(fan_in);
		scanner = g_scanners[scan];
		go(scanner(fan_in_local, sock, target));
	}

	while (nport)
	{
		int res;
		if ((res = choose(clauses, nport, -1)) < 0)
			printf("choose failed\n");
		nhost--;
		printf("finished scanning port %i\n", res);
	}

	chsend(ch, &host, sizeof(host), -1);
	hclose(ch);
}

coroutine void	nmap_scan_host(int ch, t_data *data, t_target target)
{
	int			fan_in;
	int			fan_in_local;
	t_target	target;
	int			port;

	fan_in = chmake(sizeof(t_scan_result * SCAN_MAX));
	while (port = bitfield_lsb(data.ports, USHRT_MAX + 1))
	{
		data.ports &= ~port;
		fan_in_local = hdup(fan_in);
		target.port = port;
		go(nmap_scan_port(fan_in_local, data, port));
	}

	while (nport)
	{
		int res;
		if ((res = choose(clauses, nport, -1)) < 0)
			printf("choose failed\n");
		nhost--;
		printf("finished scanning port #%i\n", res);
	}

	chsend(ch, &host, sizeof(host), -1);
	hclose(ch);
}

void	nmap(t_data *data)
{
	t_list		*list;
	t_host		*host;
	int			nhost;
	int			fan_in_local;
	struct chclause	clause[ft_lstsize(data->host)];
	int			buf;

	nhost = 0;
	for (t_list *list = data->host; list != NULL; list = list->next)
	{
		host = list->content;
		fan_in_local = hdup(fan_in);
		target.host = host;
		go(nmap_scan_host(fan_in_local, data, target));
		nhost++;
	}

	while (nhost)
	{
		int res;
		if ((res = choose(clauses, nhost, -1)) < 0)
			printf("choose failed\n");
		nhost--;
		printf("host %s has finished scanning\n", host->dn);
	}
	printf("nmap has finished\n");
	return (fan_in);
}
