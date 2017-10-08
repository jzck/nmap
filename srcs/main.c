/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/08 19:10:04 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/08 21:27:57 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

#define NMAP_USAGE1	" [--ip HOST] [--file FILE]"
#define NMAP_USAGE2	" [--ports PORTS] [--speedup [NUMBER]] [--scan [TYPE]] HOST"

int		nmap_ports(t_data *data, int ch)

int		main(int ac, char **av)
{
	t_data				data;

	if (getuid() != 0)
	{
		fprintf(stderr, "You must have root privileges to use nmap!\n");
		return(1);
	}
	if (nmap_parse(ac, av, &data))
	{
		printf("usage: nmap --help\n");
		printf("or     nmap"NMAP_USAGE1 NMAP_USAGE2"\n");
		exit(1);
	}

	// single tcp port
	struct sockaddr_in	sa;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	if (reserve_port(data.sock_tcp, &sa))
	{
		fprintf(stderr, "couldn't reserve port\n");
		exit(1);
	}

	go(nmap_listener(&data));
	int chan = nmap(&data);
	nmap_collector(chan, &data);
	return (0);
}
