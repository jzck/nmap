/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/08 19:10:04 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/09 15:58:02 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

#define NMAP_USAGE1	" [--ip HOST] [--file FILE]"
#define NMAP_USAGE2	" [--ports PORTS] [--speedup [NUMBER]] [--scan [TYPE]] HOST"

/*
** only IPv4
** only default network if
** one per port per scan type
*/
int		fill_ports(t_data *data)
{
	int		i;

	i = -1;
	while (++i < SCAN_MAX)
	{
		if ((data->sock[i] = socket(AF_INET, SOCK_RAW, 0)) < 0)
		{
			perror("socket");
			exit(1);
		}
		/* if (setsockopt(data->sock[i], IPPROTO_IP, IP_HDRINCL, (int[]){1}, sizeof(val)) == -1) */
		/* 	return (1); */
		data->sock_a[i].sin_family = AF_INET;
		data->sock_a[i].sin_addr.s_addr = INADDR_ANY;
		if (reserve_port(data.sock[i], &data.sock_a[i]))
		{
			fprintf(stderr, "couldn't reserve port\n");
			exit(1);
		}
	}
}

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
	fill_ports(&data);
	go(nmap_listener(&data));
	int chan = nmap(&data);
	return (0);
}
