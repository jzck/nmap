#include "nmap.h"

static pcap_t *pcap_obj = NULL;

static void packet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)

{
	(void)pkthdr;
	(void)packet;
	t_data *data = (t_data*)arg;
	ft_printf("received packet !!!\n");
	hexdump(&packet, sizeof(packet));
	host = extract_host(pkt);
	dport = extract_dport(pkt);
	sport = extract_sport(pkt);

	chan = get_chan(host, dport, sport);
	chsend(ch, &pkt, sizeof(pkt), -1);
}

coroutine void	nmap_listener(t_data *data)
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
	ft_printf("listener loop\n");
	if (pcap_loop(pcap_obj, -1, packet_callback, (u_char*)data) == -1)
	{
		ft_printf("pcap_loop fail\n");
		exit(EXIT_FAILURE);
	}
	free(str);
}
