/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   format.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/24 15:07:14 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 21:48:03 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

int				g_njobs;
char			g_port_status[][20] =
{
	"OPEN",
	"FILTERED",
	"CLOSED",
	"UNFILTERED",
	"OPEN_FILTERED",
};

void		nmap_format(chan results)
{
	t_result	result;
	char		buf[IPADDR_MAXSTRLEN];
	int			i;

	i = 0;
	while (i++ < g_njobs)
	{
		result = chr(results, t_result);
		printf("%s:%i %s(%s)\n",
				ipaddrstr(result.dest, buf),
				ipport(result.dest),
				g_port_status[result.status],
				result.scan);
	}
	DG("finished reading %i jobs\n", g_njobs);
}
