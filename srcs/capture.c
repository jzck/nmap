
#include "nmap.h"

#define PCAP_FILTER "src host %s and src port %i and dst host %s and dst port %i"

pcap_t		*nmap_capture(ipaddr dst, ipaddr src)
{
	char			errbuf[PCAP_ERRBUF_SIZE];
	pcap_t			*handle;
	bpf_u_int32		netp;
	bpf_u_int32		maskp;
	char			buf[IPADDR_MAXSTRLEN];
	struct bpf_program fp;
	char	str[100];

	if (pcap_lookupnet("any", &netp, &maskp, errbuf) == -1)
	{
		exit(EXIT_FAILURE);
	}
	if (!(handle = pcap_open_live("any", BUFSIZ, 0, -1, errbuf)))
	{
		fprintf(stderr, "pcap_open_live: %s", errbuf);
		exit(EXIT_FAILURE);
	}
	if (pcap_setdirection(handle, PCAP_D_IN))
		exit(EXIT_FAILURE);
	if (!(sprintf(str, PCAP_FILTER, ipaddrstr(dst, buf), ipport(dst),
									ipaddrstr(src, buf), ipport(src))))
		exit(EXIT_FAILURE);
	DG("filter is: %s", str);
	if (pcap_compile(handle, &fp, str, 1, netp) == -1)
		exit(EXIT_FAILURE);
	if (pcap_setfilter(handle, &fp) == -1)
		exit(EXIT_FAILURE);
	return (handle);
}
