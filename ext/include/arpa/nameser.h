
/*
 * Copyright (c) 1983, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef _ARPA_NAMESER_H_
#define _ARPA_NAMESER_H_


/*
* Values for class field
*/
typedef enum __ns_class {
    ns_c_in = 1,		/* Internet. */
    /* Class 2 unallocated/unsupported. */
    ns_c_chaos = 3,		/* MIT Chaos-net. */
    ns_c_hs = 4,		/* MIT Hesiod. */
    /* Query class values which do not appear in resource records */
    ns_c_none = 254,	/* for prereq. sections in update requests */
    ns_c_any = 255,		/* Wildcard match. */
    ns_c_max = 65536
} ns_class;

/*
* Currently defined type values for resources and queries.
*/
typedef enum __ns_type {
    ns_t_a = 1,		/* Host address. */
    ns_t_ns = 2,		/* Authoritative server. */
    ns_t_md = 3,		/* Mail destination. */
    ns_t_mf = 4,		/* Mail forwarder. */
    ns_t_cname = 5,		/* Canonical name. */
    ns_t_soa = 6,		/* Start of authority zone. */
    ns_t_mb = 7,		/* Mailbox domain name. */
    ns_t_mg = 8,		/* Mail group member. */
    ns_t_mr = 9,		/* Mail rename name. */
    ns_t_null = 10,		/* Null resource record. */
    ns_t_wks = 11,		/* Well known service. */
    ns_t_ptr = 12,		/* Domain name pointer. */
    ns_t_hinfo = 13,	/* Host information. */
    ns_t_minfo = 14,	/* Mailbox information. */
    ns_t_mx = 15,		/* Mail routing information. */
    ns_t_txt = 16,		/* Text strings. */
    ns_t_rp = 17,		/* Responsible person. */
    ns_t_afsdb = 18,	/* AFS cell database. */
    ns_t_x25 = 19,		/* X_25 calling address. */
    ns_t_isdn = 20,		/* ISDN calling address. */
    ns_t_rt = 21,		/* Router. */
    ns_t_nsap = 22,		/* NSAP address. */
    ns_t_nsap_ptr = 23,	/* Reverse NSAP lookup (deprecated). */
    ns_t_sig = 24,		/* Security signature. */
    ns_t_key = 25,		/* Security key. */
    ns_t_px = 26,		/* X.400 mail mapping. */
    ns_t_gpos = 27,		/* Geographical position (withdrawn). */
    ns_t_aaaa = 28,		/* Ip6 Address. */
    ns_t_loc = 29,		/* Location Information. */
    ns_t_nxt = 30,		/* Next domain (security). */
    ns_t_eid = 31,		/* Endpoint identifier. */
    ns_t_nimloc = 32,	/* Nimrod Locator. */
    ns_t_srv = 33,		/* Server Selection. */
    ns_t_atma = 34,		/* ATM Address */
    ns_t_naptr = 35,	/* Naming Authority PoinTeR */
    /* Query type values which do not appear in resource records. */
    ns_t_ixfr = 251,	/* Incremental zone transfer. */
    ns_t_axfr = 252,	/* Transfer zone of authority. */
    ns_t_mailb = 253,	/* Transfer mailbox records. */
    ns_t_maila = 254,	/* Transfer mail agent records. */
    ns_t_any = 255,		/* Wildcard match. */
    ns_t_max = 65536
} ns_type;

#endif /* !_ARPA_NAMESER_H_ */