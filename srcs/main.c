#include "nmap.h"

#define NMAP_USAGE1	" [--ip HOST] [--file FILE]"
#define NMAP_USAGE2	" [--ports PORTS] [--speedup [NOMBRE]] [--scan [TYPE]] HOST"


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
