/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ping.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/22 14:10:24 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/08 21:27:51 by jhalford         ###   ########.fr       */
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
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/if_ether.h>
# include <pcap.h>
# include <sys/wait.h>
# include <pthread.h>
# include <ifaddrs.h>

# include "libdill.h"

# define SCAN_TCP	(1 << 0)
# define SCAN_SYN	(1 << 1)
# define SCAN_NULL	(1 << 2)
# define SCAN_ACK	(1 << 3)
# define SCAN_FIN	(1 << 4)
# define SCAN_XMAS	(1 << 5)
# define SCAN_UDP	(1 << 6)
# define SCAN_MAX	7

typedef struct s_data	t_data;
typedef struct s_host	t_host;
typedef struct s_tcp_packet	t_tcp_packet;
typedef enum e_port_status	t_port_status;

struct				s_data
{
	t_flag			flag;
	char			**av_data;
	t_list			*host;

	int				sock_tcp;
	int				threads;
	int				scan;
};

struct				

enum	e_port_status
{
	OPEN,
	FILTERED,
	CLOSED,
	UNFILTERED,
	OPEN_FILTERED,
};

struct				s_host
{
	char			*host;					// user input host (ip or dn)
	char			*dn;					// ai_canonname
	char			ip[INET6_ADDRSTRLEN];	// readable ip address (4 or 6)
	struct s_target	ports[USHRT_MAX + 1];
	struct sockaddr	*addr;
	size_t			addrlen;
};

struct				s_target
{
	int				in_channel;
	t_port_status	results[SCAN_MAX];
};

struct	s_tcp_packet
{
	struct iphdr iph;
	struct tcphdr tcph;
}__attribute__((packed));

static t_cliopts	g_opts[];
int		nmap_parse(int ac, char **av, t_data *data);

void	nmap(t_data *data);
void	nmap_listener(void *arg);

#endif
