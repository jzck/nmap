/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ip.c                                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/24 17:22:16 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/26 17:10:53 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

/*
**	some libmill ip extensions
*/

uint16_t	ipport(ipaddr ip)
{
	return (ntohs(((struct sockaddr_in*)&ip)->sin_port));
}

uint16_t	ipfamily(ipaddr ip)
{
	return (((struct sockaddr*)&ip)->sa_family);
}

uint16_t	ipmode(ipaddr ip)
{
	if (((struct sockaddr*)&ip)->sa_family == AF_INET)
		return (IPADDR_IPV4);
	else
		return (IPADDR_IPV6);
}

ipaddr		iplocal_randport(const char *name, int mode, int sock)
{
	unsigned short	port;
	ipaddr			ip;

	port = 49152;
	while (port < 65535)
	{
		ip = iplocal(name, port, mode);
		if (bind(sock, (struct sockaddr*)&ip, sizeof(ip)) == 0)
			return (ip);
		++port;
	}
	errno = EBUSY;
	return (ip);
}
