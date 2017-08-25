/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   nmap.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/22 14:10:24 by jhalford          #+#    #+#             */
/*   Updated: 2017/04/23 18:18:41 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int		nmap_scan_syn(int sockfd, struct addrinfo *p)
{
	if (connect(sockfd, p->ai_addr, p->ai_addrlen))
		printf("connect failed");
	else
		printf("connect success");
	return (0);
}

int		nmap_scan(char *host, int port, int scan)
{

	struct sockaddr_in	*addr;
	struct addrinfo		*servinfo, hints;
	char				addrstr[INET_ADDRSTRLEN];
	int					sockfd;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = AI_CANONNAME;

	(void)scan;
	printf("SCAN @ %s:%i\n", host, port);
	if (getaddrinfo(host, "http", &hints, &servinfo))
	{
		fprintf(stderr, "Failed to resolve \"%s\"\n", host);
		return (1);
	}
	addr = (struct sockaddr_in*)servinfo->ai_addr;
	inet_ntop(AF_INET, &(addr->sin_addr), addrstr, INET_ADDRSTRLEN);

	/* MUST DO AND rDNS search here */
	/* printf("rDNS record for %s: %s\n", addrstr, DOMAIN NAME WITH RDNS); */

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		perror("server: socket");

	nmap_scan_syn(sockfd);

	freeaddrinfo(servinfo); 

	return (0);
}

void	nmap(t_data *data)
{
	while (data->host)
	{
		nmap_scan(data->host, 80, SCAN_TCP);
		break ;
	}
}

