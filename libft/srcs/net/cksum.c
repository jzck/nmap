/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   cksum.c                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/08 12:45:43 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/08 12:48:41 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "net.h"

unsigned short	cksum(const void *b, size_t len)
{
	unsigned int	sum;

	sum = 0;
	while (len > 1)
	{
		sum += *((uint16_t*)b++);
		b++;
		len -= 2;
	}
	if (len == 1)
		sum += *(uint8_t*)b;
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);
	return (~sum);
}
