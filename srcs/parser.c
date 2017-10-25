/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parser.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/08 19:10:05 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 21:00:10 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

extern int g_njobs;

/* static t_cliopts	g_opts[] = */
/* { */
/* 	{'h', "host", 0, 0, nmap_get_host, 0}, */
/* 	/1* {'f', "file", 0, 0, nmap_get_file, 0}, *1/ */
/* 	/1* {'p', "ports", 0, 0, nmap_get_ports, 0}, *1/ */
/* 	{'t', "threads", 0, 0, nmap_get_threads, 0}, */
/* 	{'s', "scan", 0, 0, nmap_get_scan, 0}, */
/* 	{0, 0, 0, 0, 0, 0}, */
/* }; */

/* static t_host		nmap_get_host(char *node) */
/* { */
/* 	t_host	host; */
/* 	struct addrinfo		*servinfo, hints; */

/* 	memset (&hints, 0, sizeof (hints)); */
/* 	hints.ai_family = PF_UNSPEC; */
/* 	hints.ai_socktype = SOCK_RAW; */
/* 	hints.ai_flags = AI_CANONNAME; */

/* 	if (getaddrinfo(node, NULL, &hints, &servinfo)) */
/* 	{ */
/* 		fprintf(stderr, "Failed to resolve \"%s\"\n", node); */
/* 		return (host); */
/* 	} */
/* 	host.addr = servinfo->ai_addr; */
/* 	host.addrlen = servinfo->ai_addrlen; */
/* 	host.host = node; */
/* 	host.dn = servinfo->ai_canonname; */

/* 	void *addr; */
/* 	if (servinfo->ai_family == AF_INET) { // IPv4 */
/* 		struct sockaddr_in *ipv4 = (struct sockaddr_in *)servinfo->ai_addr; */
/* 		addr = &(ipv4->sin_addr); */
/* 	} else { // IPv6 */
/* 		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)servinfo->ai_addr; */
/* 		addr = &(ipv6->sin6_addr); */
/* 	} */

/* 	// convert the IP to a string and print it: */
/* 	inet_ntop(servinfo->ai_family, addr, host.ip, sizeof(host.ip)); */

/* 	printf("dn=%s, ip=%s\n", host.dn, host.ip); */

/* 	/1* MUST DO rDNS search here *1/ */
/* 	/1* printf("rDNS record for %s: %s\n", addrstr, DOMAIN NAME WITH RDNS); *1/ */
/* 	return (host); */
/* } */

/* int		nmap_get_file(char *opt_arg, t_data *data) */
/* { */
/* } */

/* int		nmap_get_ports(char *opt_arg, t_data *data) */
/* { */
/* } */

/* static int		nmap_get_threads(char *opt_arg, t_data *data) */
/* { */
/* 	data->threads = ft_atoi(opt_arg); */
/* 	return (0); */
/* } */

/* static int		nmap_get_scan(char *opt_arg, t_data *data) */
/* { */
/* 	while (*opt_arg) */
/* 	{ */
/* 		if (*opt_arg == 'T') */
/* 			bitfield_biton(data->scans, SCAN_TCP); */
/* 		else if (*opt_arg == 'S') */
/* 			bitfield_biton(data->scans, SCAN_SYN); */
/* 		else if (*opt_arg == 'A') */
/* 			bitfield_biton(data->scans, SCAN_ACK); */
/* 		else if (*opt_arg == 'F') */
/* 			bitfield_biton(data->scans, SCAN_FIN); */
/* 		else if (*opt_arg == 'X') */
/* 			bitfield_biton(data->scans, SCAN_XMAS); */
/* 		else if (*opt_arg == 'U') */
/* 			bitfield_biton(data->scans, SCAN_UDP); */
/* 		else */
/* 			return (1); */
/* 		opt_arg++; */
/* 	} */
/* 	return (0); */
/* } */

coroutine void	coarse_dispatcher(chan jobs)
{
	t_job	job;

	job.scan = nmap_scan_tcp;

	job.dest = ipremote("scanme.nmap.org", 80, IPADDR_IPV4, -1);
	chs(jobs, t_job, job);
	/* job.dest = ipremote("scanme.nmap.org", 81, IPADDR_IPV4, -1); */
	/* chs(jobs, t_job, job); */

	job.scan = 0;
	DG("sending done job");
	chdone(jobs, t_job, job);
	chclose(jobs);
}

chan	nmap_parse(int ac, char **av)
{
	(void)ac;
	(void)av;
	/* if (cliopts_get(av, g_opts, data)) */
	/* 	return (ft_perror("nmap")); */
	/* if (!data->host && data->av_data && data->av_data) */
	/* 	nmap_get_host(*data->av_data, data); */

	chan	jobs;
	jobs = chmake(t_job, 0);

	/* ft_usage("nmap"NMAP_USAGE1 NMAP_USAGE2); */

	go(coarse_dispatcher(jobs));
	g_njobs = 1;

	return (chdup(jobs));
}
