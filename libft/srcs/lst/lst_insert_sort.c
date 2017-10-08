/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   lst_insert_sort.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ariard <ariard@student.42.fr>              +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/20 19:59:41 by ariard            #+#    #+#             */
/*   Updated: 2017/05/20 20:05:32 by ariard           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		lst_insert_sort(t_list **head,
			int (cmp)())
{
	t_list	*new;
	t_list	*ptr;

	new = NULL;
	while (*head)
	{
		ptr = *head;
		*head = (*head)->next;
		ft_lst_sorted_insert(&new, ptr, cmp);
	}
	*head = new;
}
