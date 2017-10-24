/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ping.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/22 14:10:24 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 21:29:35 by jhalford         ###   ########.fr       */
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
# include <netinet/tcp.h>
# include <netinet/ip_icmp.h>
# include <netinet/if_ether.h>
# include <pcap.h>
# include <sys/wait.h>
# include <pthread.h>
# include <ifaddrs.h>

# include "libmill.h"

typedef struct s_data	t_data;
typedef struct s_host	t_host;
typedef struct s_tcp_packet	t_tcp_packet;
typedef struct s_job	t_job;
typedef struct s_result	t_result;
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
};

struct				s_host
{
	char			*host;								// user input host (ip or dn)
	char			*dn;								// ai_canonname
	char			ip[INET6_ADDRSTRLEN];				// humain readable ip address
	struct sockaddr	*addr;
	size_t			addrlen;
};

struct				s_job
{
	ipaddr			dest;
	void			(*scan)();
};

struct				s_result
{
	ipaddr			dest;
	char			scan[4];
	t_port_status	status;
};

extern t_cliopts	g_opts[];
extern int			g_njobs;
chan				nmap_parse(int ac, char **av);
void				nmap_format(chan results);

coroutine void		nmap_scan_tcp(chan results, t_job job);
chan				nmap_listener(ipaddr dst, ipaddr src);

/*
**	IP helpers
*/
uint16_t	ipport(ipaddr ip);
uint16_t	ipmode(ipaddr ip);
uint16_t	ipfamily(ipaddr ip);
ipaddr		iplocal_randport(const char *name, int mode, int sock);

#endif
