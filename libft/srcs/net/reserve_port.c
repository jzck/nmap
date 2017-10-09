/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   reserve_port.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/07 18:02:55 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/09 10:48:18 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "net.h"

int	reserve_port(int s, struct sockaddr *sa)
{
	unsigned short		i;

	i = 49152;
	while (i < 65535)
	{
		sa->sin_port = htons(i);
		if (bind(s, sa, sizeof(sa)) == 0)
			return (0);
		++i;
	}
	return (1);
}
