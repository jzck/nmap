/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   prettypacket.h                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: jhalford <jack@crans.org>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/24 21:38:38 by jhalford          #+#    #+#             */
/*   Updated: 2017/10/24 21:41:44 by jhalford         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef __PRETTYPACKET_H__
#define __PRETTYPACKET_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hexstring.h"

/**
 * Enable disable colored output (enabled by default)
 */
static int colored_output = 1;

/**
 * List of available colors
 */
static const char *colors[] = {
    /// Black
    "\\e[0;30m",
    /// Red
    "\\e[0;31m",
    /// Green
    "\\e[0;32m",
    /// Yellow
    "\\e[0;33m",
    /// Blue
    "\\e[0;34m",
    /// Purple
    "\\e[0;35m",
    /// Cyan
    "\\e[0;36m",
    /// White
    "\\e[0;37m",
};

/**
 * Reset color
 */
static const char *color_reset = "\\e[0m";

/**
 * Default terminal rows
 */
static const int rows = 24;

/**
 * Default terminal columns
 */
static const int cols = 80;

/**
 * Example ARP packet
 */
static const char arp_packet[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xAA\x00\x04\x00\x0A\x04\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xAA\x00\x04\x00\x0A\x04\xC0\xA8\x01\x09\x00\x00\x00\x00\x00\x00\xC0\xA8\x01\x04";

/**
 * Example TCP packet
 */
static const char tcp_packet[] = "\x1C\xAF\xF7\x6B\x0E\x4D\xAA\x00\x04\x00\x0A\x04\x08\x00\x45\x00\x00\x34\x5A\xAE\x40\x00\x40\x06\x5E\x67\xC0\xA8\x01\x09\x58\xBF\x67\x3E\x9B\x44\x00\x50\x8E\xB5\xC6\xAC\x15\x93\x47\x9E\x80\x10\x00\x58\xA5\xA0\x00\x00\x01\x01\x08\x0A\x00\x09\xC3\xB2\x42\x5B\xFA\xD6";

/**
 * Example ICMP packet
 */
static const char icmp_packet[] = "\x1C\xAF\xF7\x6B\x0E\x4D\xAA\x00\x04\x00\x0A\x04\x08\x00\x45\x00\x00\x54\x00\x00\x40\x00\x40\x01\x54\x4E\xC0\xA8\x01\x09\xC0\xA8\x64\x01\x08\x00\x34\x98\xD7\x10\x00\x01\x5B\x68\x98\x4C\x00\x00\x00\x00\x2D\xCE\x0C\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37";

/**
 * Example UDP packet
 */
static const char udp_packet[] = "\x1C\xAF\xF7\x6B\x0E\x4D\xAA\x00\x04\x00\x0A\x04\x08\x00\x45\x00\x00\x3C\x9B\x23\x00\x00\x40\x11\x70\xBC\xC0\xA8\x01\x09\xD0\x43\xDC\xDC\x91\x02\x00\x35\x00\x28\x6F\x0B\xAE\x9C\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6F\x6F\x67\x6C\x65\x03\x63\x6F\x6D\x00\x00\x01\x00\x01";

/**
 * Example IGMP packet
 */
static const char igmp_packet[] = "\x1C\xAF\xF7\x6B\x0E\x4D\xAA\x00\x04\x00\x0A\x04\x08\x00\x45\x00\x00\x1C\x00\x00\x40\x00\x40\x02\x54\x4E\xC0\xA8\x01\x09\xC0\xA8\x64\x01\x11\xFF\x0D\xFF\xE0\x00\x00\x01";

/**
 * Example Spanning Tree Protocol (STP) packet
 */
static const char stp_packet[]="\x01\x80\xc2\x00\x00\x00\x00\x1c\x0e\x87\x85\x04\x00\x26\x42\x42\x03\x00\x00\x00\x00\x00\x80\x64\x00\x1c\x0e\x87\x78\x00\x00\x00\x00\x04\x80\x64\x00\x1c\x0e\x87\x85\x00\x80\x04\x01\x00\x14\x00\x02\x00\x0f\x00";

// functions that need prototypes
void layer_2_dispatcher(const char *, int, uint64_t);
void layer_3_dispatcher(const char *, int, uint64_t);
void layer_4_dispatcher(const char *, int, uint64_t);

#endif /* __PRETTYPACKET_H__ */
