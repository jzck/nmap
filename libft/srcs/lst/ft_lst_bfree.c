/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lst_bfree.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/07 16:55:04 by jhalford          #+#    #+#             */
/*   Updated: 2017/05/15 21:35:59 by ariard           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lst_bfree(void *ptr, size_t size)
{
	t_list	*lst;

	lst = ptr;
	(void)size;
	if (lst)
	{
		ft_strdel((char **)&lst->content);
		free(lst);
	}
}
