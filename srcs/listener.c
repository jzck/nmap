#include "nmap.h"

static pcap_t *pcap_obj = NULL;

static void packet_callback(u_char *tmp, const struct pcap_pkthdr *pkthdr, const u_char *packet)

{
	(void)tmp;
	(void)pkthdr;
	(void)packet;
	printf("received packet !!!\n");
}

void	*nmap_listener(void *arg)
{
	t_data *data;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct bpf_program fp;
	char *str;

	data = (t_data*)arg;
	if (pcap_lookupnet("any", &netp, &maskp, errbuf) == -1)
	{
		exit(EXIT_FAILURE);
	}
	if (!(pcap_obj = pcap_open_live("any", BUFSIZ, 0, -1, errbuf)))
	{
		fprintf(stderr, "pcap_open_live: %s", errbuf);
		exit(EXIT_FAILURE);
	}
	if (!(str = ft_str3join("host ", ((t_host*)data->host->content)->ip, " and (tcp or icmp)")))
	{
		exit(EXIT_FAILURE);
	}
	if (pcap_compile(pcap_obj, &fp, str, 1, netp) == -1)
	{
		exit(EXIT_FAILURE);
	}
	if (pcap_setfilter(pcap_obj, &fp) == -1)
	{
		exit(EXIT_FAILURE);
	}
	/* signal(SIGALRM, sigalrm_handler); */
	printf("listener loop\n");
	fflush(stdout);
	if (pcap_loop(pcap_obj, -1, packet_callback, (u_char*)data) == -1)
	{
		exit(EXIT_FAILURE);
	}
	free(str);
	return (NULL);
}
