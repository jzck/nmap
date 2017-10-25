/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   prettypacket.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/24 21:38:38 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 21:41:44 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef __PRETTYPACKET_H__
#define __PRETTYPACKET_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hexstring.h"

// functions that need prototypes
void layer_2_dispatcher(const char *, int, uint64_t);
void layer_3_dispatcher(const char *, int, uint64_t);
void layer_4_dispatcher(const char *, int, uint64_t);

#endif /* __PRETTYPACKET_H__ */
