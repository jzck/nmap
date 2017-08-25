/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ping.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/22 14:10:24 by jhalford          #+#    #+#             */
/*   Updated: 2017/04/22 15:52:07 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PING_H
# define FT_PING_H

# include "libft.h"
# include <fcntl.h>
# include <errno.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <resolv.h>
# include <netdb.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/if_ether.h>
# include <arpa/inet.h>
# include <pcap.h>
# include <sys/wait.h>

# define SCAN_TCP	(1 << 0)
# define SCAN_SYN	(1 << 1)
# define SCAN_NULL	(1 << 2)
# define SCAN_ACK	(1 << 3)
# define SCAN_FIN	(1 << 4)
# define SCAN_XMAS	(1 << 5)
# define SCAN_UDP	(1 << 6)

typedef struct s_data	t_data;

struct	s_data
{
	t_flag	flag;
	char	**av_data;
	char	*host;
	t_list	*port;
	int		threads;
	int		scan;
};

static t_cliopts	g_opts[];

void	nmap(t_data *data);

#endif
