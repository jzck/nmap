/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/08 19:10:04 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/26 16:06:16 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "nmap.h"

#define NMAP_USAGE1	" [--ip HOST] [--file FILE]"
#define NMAP_USAGE2	" [--ports PORTS] [--speedup [NUMBER]] [--scan [TYPE]] HOST"

t_data	*g_data;

coroutine void	jobs_loop(chan jobs, chan results)
{
	t_job	job;
	chan	copy;
	int		i;
	
	i = 0;
	while (1)
	{
		DG("before chr jobs");
		job = chr(jobs, t_job);
		DG("after chr jobs");
		if (job.scan == NULL)
			break ;
		copy = chdup(results);
		go(job.scan(copy, job));
		i++;
	}
	printf("finished starting jobs\n");
}

static chan		nmap(chan jobs)
{
	chan	results;

	results = chmake(t_result, 0);
	go(jobs_loop(jobs, results));
	return (results);
}

int			main(int ac, char **av)
{
	chan		jobs;
	chan		results;

	/* if (getuid() != 0) */
	/* { */
	/* 	fprintf(stderr, "You must have root privileges to use nmap\n"); */
	/* 	return(1); */
	/* } */
	jobs = nmap_parse(ac, av);
	results = nmap(jobs);
	nmap_format(results);
	return (0);
}
