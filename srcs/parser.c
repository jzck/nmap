#include "nmap.h"

int		nmap_get_host(char *node, t_data *data)
{
	t_host	host;
	struct addrinfo		*servinfo, hints;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(node, NULL, &hints, &servinfo))
	{
		fprintf(stderr, "Failed to resolve \"%s\"\n", node);
		return (1);
	}
	host.addr = servinfo->ai_addr;
	host.addrlen = servinfo->ai_addrlen;
	host.node = node;
	host.dn = servinfo->ai_canonname;

	void *addr;
	if (servinfo->ai_family == AF_INET) { // IPv4
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
		addr = &(ipv4->sin_addr);
	} else { // IPv6
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)servinfo->ai_addr;
		addr = &(ipv6->sin6_addr);
	}

	// convert the IP to a string and print it:
	inet_ntop(servinfo->ai_family, addr, host.ip, sizeof(host.ip));


	printf("dn=%s\n", host.dn);
	printf("ip=%s\n", host.ip);

	/* MUST DO AND rDNS search here */
	/* printf("rDNS record for %s: %s\n", addrstr, DOMAIN NAME WITH RDNS); */

	if ((host.sock_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		perror("server: socket");

	int val = 1;
	if (setsockopt(host.sock_tcp, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) == -1)
		return (1);

	ft_lsteadd(&data->host, ft_lstnew(&host, sizeof(host)));
	return (0);
}

/* int		nmap_get_file(char *opt_arg, t_data *data) */
/* { */
/* } */

/* int		nmap_get_ports(char *opt_arg, t_data *data) */
/* { */
/* } */

int		nmap_get_threads(char *opt_arg, t_data *data)
{
	data->threads = ft_atoi(opt_arg);
	return (0);
}

int		nmap_get_scan(char *opt_arg, t_data *data)
{
	while (*opt_arg)
	{
		if (*opt_arg == 'T')
			data->scan |= SCAN_TCP;
		else if (*opt_arg == 'S')
			data->scan |= SCAN_SYN;
		else if (*opt_arg == 'N')
			data->scan |= SCAN_NULL;
		else if (*opt_arg == 'A')
			data->scan |= SCAN_ACK;
		else if (*opt_arg == 'F')
			data->scan |= SCAN_FIN;
		else if (*opt_arg == 'X')
			data->scan |= SCAN_XMAS;
		else if (*opt_arg == 'U')
			data->scan |= SCAN_UDP;
		else
			return (1);
		opt_arg++;
	}
	return (0);
}

