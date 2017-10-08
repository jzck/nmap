/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putendl.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/03 14:57:40 by jhalford          #+#    #+#             */
/*   Updated: 2017/02/20 18:17:01 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_putendl_fd(char const *s, int fd)
{
	char	nl;
	int		ret;

	nl = '\n';
	if ((ret = write(fd, s, ft_strlen(s))))
		return (ret);
	return (write(fd, &nl, 1));
}

int	ft_putendl(char const *s)
{
	return (ft_putendl_fd(s, 1));
}
