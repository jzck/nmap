/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/08 19:10:04 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 20:08:00 by jhalford         ###   ########.fr       */
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
	while (true)
	{
		job = chr(jobs, t_job);
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
	/* 	fprintf(stderr, "You must have root privileges to use nmap!\n"); */
	/* 	return(1); */
	/* } */
	if ((jobs = nmap_parse(ac, av)) < 0)
	{
		printf("usage: nmap --help\n");
		printf("or     nmap"NMAP_USAGE1 NMAP_USAGE2"\n");
		exit(1);
	}
	results = nmap(jobs);
	nmap_format(results);
	return (0);
}
