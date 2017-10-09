/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bitfield.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/09 14:44:16 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/09 15:57:25 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

/*
**	==== Wrapper around GCC builtins for	====
**	==== arbitrarily large sized bitfields	====
**	
**	todo
**		- up and down iterator
**		
*/
typedef uint64_t		t_bitblock;

#define BITFIELD(var, size)	t_bitblock		var[size / sizeof(t_bitblock)]
#define BLOCKSIZE			(8 * sizeof(t_bitblock))

/*
** Turn bit on
*/
extern inline void	bitfield_biton(t_bitblock field[], uint64_t bit)
{
	field[bit / BLOCKSIZE] |= (1 << bit % BLOCKSIZE);
}

/*
** Turn bit off
*/
extern inline void	bitfield_bitoff(t_bitblock field[], uint64_t bit)
{
	field[bit / BLOCKSIZE] &= ~(1 << bit % BLOCKSIZE);
}

/*
** 	Least Significant Bit (rightmost)
*/
extern inline uint64_t	bitfield_lsb(t_bitblock field[], uint64_t size)
{
	int block = -1;

	while (!field[++block])
		if ((block+1) * BLOCKSIZE > size)
			return (-1);
	return (block * BLOCKSIZE + __builtin_ctzll(field[block] ^ (~field[block] + 1)) - 1);
}

/*
** Count the number of 1-bits in field
*/
extern inline uint64_t	bitfield_popcount(t_bitblock field[], uint64_t size)
{
	int block = -1;
	int count = 0;

	while (++block * BLOCKSIZE < size)
		count += __builtin_popcountll(field[block]);
	return (count);
}