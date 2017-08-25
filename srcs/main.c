#include "nmap.h"

#define NMAP_USAGE1	" [--ip HOST] [--file FILE]"
#define NMAP_USAGE2	" [--ports PORTS] [--speedup [NOMBRE]] [--scan [TYPE]] HOST"

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
	if (!data->host && data->av_data && data->av_data)
		nmap_get_host(*data->av_data, data);
	if (!data->scan)
		data->scan = SCAN_TCP;
	return (0);
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

	if (reserve_port(&data.src_port))
	{
		fprintf(stderr, "couldn't reserve port\n");
		exit(1);
	}

	pthread_t listener;
	pthread_create(&listener, NULL, &nmap_listener, &data);
	nmap(&data);
	return (0);
}
