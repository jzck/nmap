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


	nmap_scan_syn(sockfd, servinfo);

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

