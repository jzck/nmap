#include "nmap.h"

#define NMAP_USAGE1	" [--ip HOST] [--file FILE]"
#define NMAP_USAGE2	" [--ports PORTS] [--speedup [NOMBRE]] [--scan [TYPE]] HOST"

int		nmap_get_host(char *opt_arg, t_data *data)
{
	data->host = opt_arg;
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

	nmap(&data);
	return (0);
}
