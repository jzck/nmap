/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ping.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/22 14:10:24 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/09 16:14:18 by jhalford         ###   ########.fr       */
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

typedef struct s_data	t_data;
typedef struct s_host	t_host;
typedef struct s_tcp_packet	t_tcp_packet;
typedef enum e_port_status	t_port_status;
typedef enum e_scan_type	t_scan_type;

enum	e_scan_type
{
	SCAN_TCP,
	SCAN_SYN,
	SCAN_ACK,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_UDP,
	SCAN_MAX
};

enum	e_port_status
{
	OPEN,
	FILTERED,
	CLOSED,
	UNFILTERED,
	OPEN_FILTERED,
};

struct				s_data
{
	t_flag			flag;
	char			**av_data;

	int				sock[SCAN_MAX];
	struct sockaddr	sock_a[SCAN_MAX];
	int				threads;

	t_list			*host;
	BITFIELD(ports, USHRT_MAX + 1);
	BITFIELD(scans, SCAN_MAX);
};

struct				s_host
{
	char			*host;								// user input host (ip or dn)
	char			*dn;								// ai_canonname
	char			ip[INET6_ADDRSTRLEN];				// humain readable ip address
	struct sockaddr	*addr;
	size_t			addrlen;
	int				chan[USHRT_MAX + 1][SCAN_MAX];
};

struct				s_target
{
	t_host			*host;
	uint16_t		port;
	t_scan_type		scan;
	#define capture_chan(t)	(t.host.chan[t.port][t.scan])
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
