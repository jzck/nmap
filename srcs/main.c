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
	if (reserve_port(&data.src_port))
	{
		fprintf(stderr, "couldn't reserve port\n");
		exit(1);
	}
	int port_chan = chmake(sizeof(int));
	go(nmap_listener(&data));
	go(nmap_ports(&data, port_chan));
	/* go(nmap_collector(&data)); */
	nmap(&data);
	return (0);
}
