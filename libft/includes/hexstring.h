/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hexstring.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/24 21:37:32 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 21:46:12 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/**
 * HEXSTRING HEADER
 * 
 * Functions used to convert, and manipulate hexstrings.
 */

#ifndef HEXSTRING_H_
# define HEXSTRING_H_

# include "libft.h"

# include <ctype.h>
# include <stdio.h>
# include <string.h>
# include <assert.h>
# include <stdint.h>


char *raw_to_hexstr(const char *raw, int size);
char *hexstr_to_raw(const char *hexstr, int *size);
void hex_to_str(uint8_t hex, char *str);
uint8_t str_to_hex(char *str);

#endif /* HEXSTRING_H_ */
