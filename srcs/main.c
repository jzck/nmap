#include "nmap.h"

#define NMAP_USAGE1	" [--ip HOST] [--file FILE]"
#define NMAP_USAGE2	" [--ports PORTS] [--speedup [NOMBRE]] [--scan [TYPE]] HOST"

int		nmap_get_host(char *opt_arg, t_data *data)
{
	t_host	*host;

	host = opt_arg;
	struct sockaddr_in	*addr;
	struct addrinfo		*servinfo, hints;
	char				addrstr[INET_ADDRSTRLEN];
	int					sockfd;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = AI_CANONNAME;

	if (getaddrinfo(host, NULL, &hints, &servinfo))
	{
		fprintf(stderr, "Failed to resolve \"%s\"\n", host);
		return (1);
	}
	host->addr = (struct sockaddr_in*)servinfo->ai_addr;
	inet_ntop(AF_INET, &(addr->sin_addr), addrstr, INET_ADDRSTRLEN);
	host->addrstr = addrstr;

	/* MUST DO AND rDNS search here */
	/* printf("rDNS record for %s: %s\n", addrstr, DOMAIN NAME WITH RDNS); */

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		perror("server: socket");

	ft_lsteadd(&data->host, &host);
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

static t_cliopts	g_opts[] =
{
	{'i', "ip", 0, 0, nmap_get_host, 0},
	/* {'f', "file", 0, 0, nmap_get_file, 0}, */
	/* {'p', "ports", 0, 0, nmap_get_ports, 0}, */
	{'t', "threads", 0, 0, nmap_get_threads, 0},
	{'s', "scan", 0, 0, nmap_get_scan, 0},
	{0, 0, 0, 0, 0, 0},
};


int		nmap_parse(int ac, char **av, t_data *data)
{
	(void)ac;
	data->host = NULL;
	data->port = 0;
	data->threads = 0;
	data->scan = 0;

	if (cliopts_get(av, g_opts, data))
		return (ft_perror("nmap"));
	if (!data->host && data->av_data)
		data->host = *data->av_data;
	if (!data->scan)
		data->scan = SCAN_TCP;
	return (0);
}

int		main(int ac, char **av)
{
	t_data				data;

	if (nmap_parse(ac, av, &data))
	{
		printf("usage: nmap --help\n");
		printf("or     nmap"NMAP_USAGE1 NMAP_USAGE2"\n");
		exit(1);
	}

	pthread_t listener;
	pthread_create(&listener, NULL, &nmap_listener, &data);
	nmap(&data);
	return (0);
}
