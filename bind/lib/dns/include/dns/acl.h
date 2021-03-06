/*
 * Copyright (C) 2004-2007, 2009, 2011  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 1999-2002  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: acl.h,v 1.35 2011/06/17 23:47:49 tbox Exp $ */

#ifndef DNS_ACL_H
#define DNS_ACL_H 1

/*****
 ***** Module Info
 *****/

/*! \file dns/acl.h
 * \brief
 * Address match list handling.
 */

/***
 *** Imports
 ***/

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/netaddr.h>
#include <isc/refcount.h>

#include <dns/name.h>
#include <dns/types.h>
#include <dns/iptable.h>

/***
 *** Types
 ***/

typedef enum {
	dns_aclelementtype_ipprefix,
	dns_aclelementtype_keyname,
	dns_aclelementtype_nestedacl,
	dns_aclelementtype_localhost,
	dns_aclelementtype_localnets,
#ifdef HAVE_GEOIP
	dns_aclelementtype_geoip_countryDB,
	dns_aclelementtype_geoip_cityDB,
	dns_aclelementtype_geoip_regionDB,
	dns_aclelementtype_geoip_ispDB,
	dns_aclelementtype_geoip_orgDB,
	dns_aclelementtype_geoip_asDB,
	dns_aclelementtype_geoip_netspeedDB,
	dns_aclelementtype_geoip_domainDB,
#endif /* HAVE_GEOIP */
	dns_aclelementtype_any
} dns_aclelementtype_t;

#ifdef HAVE_GEOIP

/* COUNTRY DB */

typedef enum {
	geoip_countryDB_country_code,
	geoip_countryDB_country_code3,
	geoip_countryDB_country_name,
} dns_geoip_subtype_countryDB_t ;

typedef struct dns_geoip_countryDB {
	dns_geoip_subtype_countryDB_t subtype ;
	char country_code[2] ;
	char country_code3[3] ;
	char country_name[256] ;	/* \0 padded */
} dns_geoip_countryDB_t;

/* CITY DB */

typedef enum {
	geoip_cityDB_country_code,
	geoip_cityDB_country_code3,
	geoip_cityDB_region,
	geoip_cityDB_region_name,
	geoip_cityDB_city,
	geoip_cityDB_postal_code,
	geoip_cityDB_range,
	geoip_cityDB_radius,
	geoip_cityDB_metro_code,
	geoip_cityDB_area_code,
	geoip_cityDB_continent_code,
	geoip_cityDB_timezone_code,
} dns_geoip_subtype_cityDB_t ;

typedef struct dns_geoip_cityDB {
	dns_geoip_subtype_cityDB_t subtype ;
	char country_code[2] ;
	char country_code3[3] ;
	char region[2] ;
	char region_name[256] ;		/* \0 padded */
	char city[256] ;		/* \0 padded */
	char postal_code[7] ;		/* \0 padded */
	float lat[2] ;
	float lon[2] ;
	float radius[2] ;
	int metro_code ;
	int area_code ;
	char continent_code[2] ;
	char timezone_code[256] ;	/* \0 padded */
} dns_geoip_cityDB_t;

/* REGION DB */

typedef enum {
	geoip_regionDB_country_code,
	geoip_regionDB_region,
} dns_geoip_subtype_regionDB_t ;

typedef struct dns_geoip_regionDB {
	dns_geoip_subtype_regionDB_t subtype ;
	char country_code[2] ;
	char region[2] ;
} dns_geoip_regionDB_t;

/* ISP DB */

typedef enum {
	geoip_ispDB_name,
} dns_geoip_subtype_ispDB_t ;

typedef struct dns_geoip_ispDB {
	dns_geoip_subtype_ispDB_t subtype ;
	char name[51] ;			/* \0 padded */
} dns_geoip_ispDB_t;

/* ORG DB */

typedef enum {
	geoip_orgDB_name,
} dns_geoip_subtype_orgDB_t ;

typedef struct dns_geoip_orgDB {
	dns_geoip_subtype_orgDB_t subtype ;
	char name[51] ;			/* \0 padded */
} dns_geoip_orgDB_t;

/* AS DB */

typedef enum {
	geoip_asDB_org,
} dns_geoip_subtype_asDB_t ;

typedef struct dns_geoip_asDB {
	dns_geoip_subtype_asDB_t subtype ;
	char org[51] ;			/* \0 padded */
} dns_geoip_asDB_t;

/* NETSPEED DB */

typedef enum {
	geoip_netspeedDB_id,
} dns_geoip_subtype_netspeedDB_t ;

typedef struct dns_geoip_netspeedDB {
	dns_geoip_subtype_netspeedDB_t subtype ;
	short int id ;
} dns_geoip_netspeedDB_t;

/* DOMAIN DB */

typedef enum {
	geoip_domainDB_name,
} dns_geoip_subtype_domainDB_t ;

typedef struct dns_geoip_domainDB {
	dns_geoip_subtype_domainDB_t subtype ;
	char name[256] ;		/* \0 padded */
} dns_geoip_domainDB_t;

#endif /* HAVE_GEOIP */

typedef struct dns_aclipprefix dns_aclipprefix_t;

struct dns_aclipprefix {
	isc_netaddr_t address; /* IP4/IP6 */
	unsigned int prefixlen;
};

struct dns_aclelement {
	dns_aclelementtype_t	type;
	isc_boolean_t		negative;
	dns_name_t		keyname;
#ifdef HAVE_GEOIP
	dns_geoip_countryDB_t	geoip_countryDB;
	dns_geoip_cityDB_t	geoip_cityDB;
	dns_geoip_regionDB_t	geoip_regionDB;
	dns_geoip_ispDB_t	geoip_ispDB;
	dns_geoip_orgDB_t	geoip_orgDB;
	dns_geoip_asDB_t	geoip_asDB;
	dns_geoip_netspeedDB_t	geoip_netspeedDB;
	dns_geoip_domainDB_t	geoip_domainDB;
#endif /* HAVE_GEOIP */
	dns_acl_t		*nestedacl;
	int			node_num;
};

struct dns_acl {
	unsigned int		magic;
	isc_mem_t		*mctx;
	isc_refcount_t		refcount;
	dns_iptable_t		*iptable;
#define node_count		iptable->radix->num_added_node
	dns_aclelement_t	*elements;
	isc_boolean_t 		has_negatives;
	unsigned int 		alloc;		/*%< Elements allocated */
	unsigned int 		length;		/*%< Elements initialized */
	char 			*name;		/*%< Temporary use only */
	ISC_LINK(dns_acl_t) 	nextincache;	/*%< Ditto */
};

struct dns_aclenv {
	dns_acl_t *localhost;
	dns_acl_t *localnets;
	isc_boolean_t match_mapped;
};

#define DNS_ACL_MAGIC		ISC_MAGIC('D','a','c','l')
#define DNS_ACL_VALID(a)	ISC_MAGIC_VALID(a, DNS_ACL_MAGIC)

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_acl_create(isc_mem_t *mctx, int n, dns_acl_t **target);
/*%<
 * Create a new ACL, including an IP table and an array with room
 * for 'n' ACL elements.  The elements are uninitialized and the
 * length is 0.
 */

isc_result_t
dns_acl_any(isc_mem_t *mctx, dns_acl_t **target);
/*%<
 * Create a new ACL that matches everything.
 */

isc_result_t
dns_acl_none(isc_mem_t *mctx, dns_acl_t **target);
/*%<
 * Create a new ACL that matches nothing.
 */

isc_boolean_t
dns_acl_isany(dns_acl_t *acl);
/*%<
 * Test whether ACL is set to "{ any; }"
 */

isc_boolean_t
dns_acl_isnone(dns_acl_t *acl);
/*%<
 * Test whether ACL is set to "{ none; }"
 */

isc_result_t
dns_acl_merge(dns_acl_t *dest, dns_acl_t *source, isc_boolean_t pos);
/*%<
 * Merge the contents of one ACL into another.  Call dns_iptable_merge()
 * for the IP tables, then concatenate the element arrays.
 *
 * If pos is set to false, then the nested ACL is to be negated.  This
 * means reverse the sense of each *positive* element or IP table node,
 * but leave negatives alone, so as to prevent a double-negative causing
 * an unexpected positive match in the parent ACL.
 */

void
dns_acl_attach(dns_acl_t *source, dns_acl_t **target);
/*%<
 * Attach to acl 'source'.
 *
 * Requires:
 *\li	'source' to be a valid acl.
 *\li	'target' to be non NULL and '*target' to be NULL.
 */

void
dns_acl_detach(dns_acl_t **aclp);
/*%<
 * Detach the acl. On final detach the acl must not be linked on any
 * list.
 *
 * Requires:
 *\li	'*aclp' to be a valid acl.
 *
 * Insists:
 *\li	'*aclp' is not linked on final detach.
 */

isc_boolean_t
dns_acl_isinsecure(const dns_acl_t *a);
/*%<
 * Return #ISC_TRUE iff the acl 'a' is considered insecure, that is,
 * if it contains IP addresses other than those of the local host.
 * This is intended for applications such as printing warning
 * messages for suspect ACLs; it is not intended for making access
 * control decisions.  We make no guarantee that an ACL for which
 * this function returns #ISC_FALSE is safe.
 */

isc_result_t
dns_aclenv_init(isc_mem_t *mctx, dns_aclenv_t *env);
/*%<
 * Initialize ACL environment, setting up localhost and localnets ACLs
 */

void
dns_aclenv_copy(dns_aclenv_t *t, dns_aclenv_t *s);

void
dns_aclenv_destroy(dns_aclenv_t *env);

isc_result_t
dns_acl_match(const isc_netaddr_t *reqaddr,
	      const dns_name_t *reqsigner,
	      const dns_acl_t *acl,
	      const dns_aclenv_t *env,
	      int *match,
	      const dns_aclelement_t **matchelt);
/*%<
 * General, low-level ACL matching.  This is expected to
 * be useful even for weird stuff like the topology and sortlist statements.
 *
 * Match the address 'reqaddr', and optionally the key name 'reqsigner',
 * against 'acl'.  'reqsigner' may be NULL.
 *
 * If there is a match, '*match' will be set to an integer whose absolute
 * value corresponds to the order in which the matching value was inserted
 * into the ACL.  For a positive match, this value will be positive; for a
 * negative match, it will be negative.
 *
 * If there is no match, *match will be set to zero.
 *
 * If there is a match in the element list (either positive or negative)
 * and 'matchelt' is non-NULL, *matchelt will be pointed to the matching
 * element.
 *
 * Returns:
 *\li	#ISC_R_SUCCESS		Always succeeds.
 */

isc_boolean_t
dns_aclelement_match(const isc_netaddr_t *reqaddr,
		     const dns_name_t *reqsigner,
		     const dns_aclelement_t *e,
		     const dns_aclenv_t *env,
		     const dns_aclelement_t **matchelt);
/*%<
 * Like dns_acl_match, but matches against the single ACL element 'e'
 * rather than a complete ACL, and returns ISC_TRUE iff it matched.
 *
 * To determine whether the match was positive or negative, the
 * caller should examine e->negative.  Since the element 'e' may be
 * a reference to a named ACL or a nested ACL, a matching element
 * returned through 'matchelt' is not necessarily 'e' itself.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_ACL_H */
