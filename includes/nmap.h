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
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/if_ether.h>
# include <pcap.h>
# include <sys/wait.h>
# include <pthread.h>
# include <ifaddrs.h>

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

struct	s_data
{
	t_flag	flag;
	char	**av_data;
	t_list	*dest_addr;
	struct sockaddr	source_addr;
	t_list	*port;
	int		threads;
	int		scan;
	int		src_port;
};

/* enum e_scan_type */
/* { */
/* 	SCAN_SYN, */
/* 	SCAN_NULL, */
/* 	SCAN_ACK, */
/* 	SCAN_FIN, */
/* 	SCAN_XMAS, */
/* 	SCAN_UDP, */
/* }; */

enum e_port_status
{
	OPEN,
	FILTERED,
	CLOSED,
	UNFILTERED,
	OPEN_FILTERED,
};

struct s_host
{
	char	*node;					// user inputed node (ip or dn)
	char	*dn;					// ai_canonname
	char	ip[INET6_ADDRSTRLEN];	// readable ip address (4 or 6)
	int		sock_tcp;
	int		sock_udp;
	int		sock_icmp;
	t_port_status results[USHRT_MAX + 1];
	char	scanning[USHRT_MAX + 1];
	struct sockaddr *addr;
	size_t	addrlen;
};

struct	s_tcp_packet
{
	struct iphdr iph;
	struct tcphdr tcph;
}__attribute__((packed));

static t_cliopts	g_opts[];
int		nmap_parse(int ac, char **av, t_data *data);

void	nmap(t_data *data);
void	*nmap_listener(void *arg);

#endif
