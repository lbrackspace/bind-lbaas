/*
 * Copyright (C) 2004-2009, 2011, 2013  Internet Systems Consortium, Inc. ("ISC")
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

/* $Id: acl.c,v 1.55 2011/06/17 23:47:49 tbox Exp $ */

/*! \file */

#include <config.h>

#include <isc/mem.h>
#include <isc/once.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/iptable.h>

#ifdef HAVE_GEOIP
#include <isc/thread.h>
#include <math.h>
#include <netinet/in.h>
#include <dns/log.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include <isc/geoip.h>

GeoIP * ns_g_geoip_countryDB = (GeoIP *)NULL ;
GeoIP * ns_g_geoip_cityDB = (GeoIP *)NULL ;
GeoIP * ns_g_geoip_regionDB = (GeoIP *)NULL ;
GeoIP * ns_g_geoip_ispDB = (GeoIP *)NULL ;
GeoIP * ns_g_geoip_orgDB = (GeoIP *)NULL ;
GeoIP * ns_g_geoip_asDB = (GeoIP *)NULL ;
GeoIP * ns_g_geoip_netspeedDB = (GeoIP *)NULL ;
GeoIP * ns_g_geoip_domainDB = (GeoIP *)NULL ;
#ifdef HAVE_GEOIP_V6
GeoIP * ns_g_geoip_countryDB_v6 = (GeoIP *)NULL ;
#endif

#ifdef ISC_PLATFORM_USETHREADS
/* CITY IPNUM v4 */
static isc_once_t prev_cityDB_ipnum_once = ISC_ONCE_INIT;
static isc_thread_key_t prev_cityDB_ipnum ;
static void
initialize_prev_cityDB_ipnum( void ) {
	RUNTIME_CHECK(isc_thread_key_create( &prev_cityDB_ipnum, (void *)NULL) == ISC_R_SUCCESS);
}
static uint32_t
get_prev_cityDB_ipnum() {
	uint32_t *preval = (uint32_t *)isc_thread_key_getspecific( prev_cityDB_ipnum );
	if ( preval )
		return *preval ;
	return 0 ;
}
static void
set_prev_cityDB_ipnum( const uint32_t in_ipnum ) {
	uint32_t *preval = (uint32_t *)isc_thread_key_getspecific( prev_cityDB_ipnum );
	if ( preval )
		free(preval);
	if (( preval = (uint32_t *)malloc( sizeof(uint32_t) ) ))
		*preval = in_ipnum ;
	isc_thread_key_setspecific( prev_cityDB_ipnum, preval );
}
/* CITY RECORD */
static isc_once_t prev_cityDB_record_once = ISC_ONCE_INIT;
static isc_thread_key_t prev_cityDB_record ;
static void
initialize_prev_cityDB_record( void ) {
	RUNTIME_CHECK(isc_thread_key_create( &prev_cityDB_record, (void *)NULL) == ISC_R_SUCCESS);
}
static GeoIPRecord *
get_prev_cityDB_record() {
	return (GeoIPRecord *)isc_thread_key_getspecific( prev_cityDB_record );
}
static void
set_prev_cityDB_record( GeoIPRecord *in_record ) {
	GeoIPRecord *preval = get_prev_cityDB_record();
	if ( preval )
		GeoIPRecord_delete( preval );
	isc_thread_key_setspecific(prev_cityDB_record, in_record);
}
#endif /* ISC_PLATFORM_USETHREADS */
#endif /* HAVE_GEOIP */

/*
 * Create a new ACL, including an IP table and an array with room
 * for 'n' ACL elements.  The elements are uninitialized and the
 * length is 0.
 */
isc_result_t
dns_acl_create(isc_mem_t *mctx, int n, dns_acl_t **target) {
	isc_result_t result;
	dns_acl_t *acl;

	/*
	 * Work around silly limitation of isc_mem_get().
	 */
	if (n == 0)
		n = 1;

	acl = isc_mem_get(mctx, sizeof(*acl));
	if (acl == NULL)
		return (ISC_R_NOMEMORY);

	acl->mctx = NULL;
	isc_mem_attach(mctx, &acl->mctx);

	acl->name = NULL;

	result = isc_refcount_init(&acl->refcount, 1);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, acl, sizeof(*acl));
		return (result);
	}

	result = dns_iptable_create(mctx, &acl->iptable);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(mctx, acl, sizeof(*acl));
		return (result);
	}

	acl->elements = NULL;
	acl->alloc = 0;
	acl->length = 0;
	acl->has_negatives = ISC_FALSE;

	ISC_LINK_INIT(acl, nextincache);
	/*
	 * Must set magic early because we use dns_acl_detach() to clean up.
	 */
	acl->magic = DNS_ACL_MAGIC;

	acl->elements = isc_mem_get(mctx, n * sizeof(dns_aclelement_t));
	if (acl->elements == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}
	acl->alloc = n;
	memset(acl->elements, 0, n * sizeof(dns_aclelement_t));
	*target = acl;
	return (ISC_R_SUCCESS);

 cleanup:
	dns_acl_detach(&acl);
	return (result);
}

/*
 * Create a new ACL and initialize it with the value "any" or "none",
 * depending on the value of the "neg" parameter.
 * "any" is a positive iptable entry with bit length 0.
 * "none" is the same as "!any".
 */
static isc_result_t
dns_acl_anyornone(isc_mem_t *mctx, isc_boolean_t neg, dns_acl_t **target) {
	isc_result_t result;
	dns_acl_t *acl = NULL;

	result = dns_acl_create(mctx, 0, &acl);
	if (result != ISC_R_SUCCESS)
		return (result);

	result = dns_iptable_addprefix(acl->iptable, NULL, 0, ISC_TF(!neg));
	if (result != ISC_R_SUCCESS) {
		dns_acl_detach(&acl);
		return (result);
	}

	*target = acl;
	return (result);
}

/*
 * Create a new ACL that matches everything.
 */
isc_result_t
dns_acl_any(isc_mem_t *mctx, dns_acl_t **target) {
	return (dns_acl_anyornone(mctx, ISC_FALSE, target));
}

/*
 * Create a new ACL that matches nothing.
 */
isc_result_t
dns_acl_none(isc_mem_t *mctx, dns_acl_t **target) {
	return (dns_acl_anyornone(mctx, ISC_TRUE, target));
}

/*
 * If pos is ISC_TRUE, test whether acl is set to "{ any; }"
 * If pos is ISC_FALSE, test whether acl is set to "{ none; }"
 */
static isc_boolean_t
dns_acl_isanyornone(dns_acl_t *acl, isc_boolean_t pos)
{
	/* Should never happen but let's be safe */
	if (acl == NULL ||
	    acl->iptable == NULL ||
	    acl->iptable->radix == NULL ||
	    acl->iptable->radix->head == NULL ||
	    acl->iptable->radix->head->prefix == NULL)
		return (ISC_FALSE);

	if (acl->length != 0 || acl->node_count != 1)
		return (ISC_FALSE);

	if (acl->iptable->radix->head->prefix->bitlen == 0 &&
	    acl->iptable->radix->head->data[0] != NULL &&
	    acl->iptable->radix->head->data[0] ==
		    acl->iptable->radix->head->data[1] &&
	    *(isc_boolean_t *) (acl->iptable->radix->head->data[0]) == pos)
		return (ISC_TRUE);

	return (ISC_FALSE); /* All others */
}

/*
 * Test whether acl is set to "{ any; }"
 */
isc_boolean_t
dns_acl_isany(dns_acl_t *acl)
{
	return (dns_acl_isanyornone(acl, ISC_TRUE));
}

/*
 * Test whether acl is set to "{ none; }"
 */
isc_boolean_t
dns_acl_isnone(dns_acl_t *acl)
{
	return (dns_acl_isanyornone(acl, ISC_FALSE));
}

/*
 * Determine whether a given address or signer matches a given ACL.
 * For a match with a positive ACL element or iptable radix entry,
 * return with a positive value in match; for a match with a negated ACL
 * element or radix entry, return with a negative value in match.
 */
isc_result_t
dns_acl_match(const isc_netaddr_t *reqaddr,
	      const dns_name_t *reqsigner,
	      const dns_acl_t *acl,
	      const dns_aclenv_t *env,
	      int *match,
	      const dns_aclelement_t **matchelt)
{
	isc_uint16_t bitlen, family;
	isc_prefix_t pfx;
	isc_radix_node_t *node = NULL;
	const isc_netaddr_t *addr;
	isc_netaddr_t v4addr;
	isc_result_t result;
	int match_num = -1;
	unsigned int i;

	REQUIRE(reqaddr != NULL);
	REQUIRE(matchelt == NULL || *matchelt == NULL);

	if (env == NULL || env->match_mapped == ISC_FALSE ||
	    reqaddr->family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(&reqaddr->type.in6))
		addr = reqaddr;
	else {
		isc_netaddr_fromv4mapped(&v4addr, reqaddr);
		addr = &v4addr;
	}

	/* Always match with host addresses. */
	family = addr->family;
	bitlen = family == AF_INET6 ? 128 : 32;
	NETADDR_TO_PREFIX_T(addr, pfx, bitlen);

	/* Assume no match. */
	*match = 0;

	/* Search radix. */
	result = isc_radix_search(acl->iptable->radix, &node, &pfx);

	/* Found a match. */
	if (result == ISC_R_SUCCESS && node != NULL) {
		match_num = node->node_num[ISC_IS6(family)];
		if (*(isc_boolean_t *) node->data[ISC_IS6(family)] == ISC_TRUE)
			*match = match_num;
		else
			*match = -match_num;
	}

	/* Now search non-radix elements for a match with a lower node_num. */
	for (i = 0; i < acl->length; i++) {
		dns_aclelement_t *e = &acl->elements[i];

		/* Already found a better match? */
		if (match_num != -1 && match_num < e->node_num) {
			isc_refcount_destroy(&pfx.refcount);
			return (ISC_R_SUCCESS);
		}

		if (dns_aclelement_match(reqaddr, reqsigner,
					 e, env, matchelt)) {
			if (match_num == -1 || e->node_num < match_num) {
				if (e->negative == ISC_TRUE)
					*match = -e->node_num;
				else
					*match = e->node_num;
			}
			isc_refcount_destroy(&pfx.refcount);
			return (ISC_R_SUCCESS);
		}
	}

	isc_refcount_destroy(&pfx.refcount);
	return (ISC_R_SUCCESS);
}

/*
 * Merge the contents of one ACL into another.  Call dns_iptable_merge()
 * for the IP tables, then concatenate the element arrays.
 *
 * If pos is set to false, then the nested ACL is to be negated.  This
 * means reverse the sense of each *positive* element or IP table node,
 * but leave negatives alone, so as to prevent a double-negative causing
 * an unexpected positive match in the parent ACL.
 */
isc_result_t
dns_acl_merge(dns_acl_t *dest, dns_acl_t *source, isc_boolean_t pos)
{
	isc_result_t result;
	unsigned int newalloc, nelem, i;
	int max_node = 0, nodes;

	/* Resize the element array if needed. */
	if (dest->length + source->length > dest->alloc) {
		void *newmem;

		newalloc = dest->alloc + source->alloc;
		if (newalloc < 4)
			newalloc = 4;

		newmem = isc_mem_get(dest->mctx,
				     newalloc * sizeof(dns_aclelement_t));
		if (newmem == NULL)
			return (ISC_R_NOMEMORY);

		/* Copy in the original elements */
		memcpy(newmem, dest->elements,
		       dest->length * sizeof(dns_aclelement_t));

		/* Release the memory for the old elements array */
		isc_mem_put(dest->mctx, dest->elements,
			    dest->alloc * sizeof(dns_aclelement_t));
		dest->elements = newmem;
		dest->alloc = newalloc;
	}

	/*
	 * Now copy in the new elements, increasing their node_num
	 * values so as to keep the new ACL consistent.  If we're
	 * negating, then negate positive elements, but keep negative
	 * elements the same for security reasons.
	 */
	nelem = dest->length;
	dest->length += source->length;
	for (i = 0; i < source->length; i++) {
		if (source->elements[i].node_num > max_node)
			max_node = source->elements[i].node_num;

		/* Copy type. */
		dest->elements[nelem + i].type = source->elements[i].type;

		/* Adjust node numbering. */
		dest->elements[nelem + i].node_num =
			source->elements[i].node_num + dest->node_count;

		/* Duplicate nested acl. */
		if (source->elements[i].type == dns_aclelementtype_nestedacl &&
		   source->elements[i].nestedacl != NULL)
			dns_acl_attach(source->elements[i].nestedacl,
				       &dest->elements[nelem + i].nestedacl);

		/* Duplicate key name. */
		if (source->elements[i].type == dns_aclelementtype_keyname) {
			dns_name_init(&dest->elements[nelem+i].keyname, NULL);
			result = dns_name_dup(&source->elements[i].keyname,
					      dest->mctx,
					      &dest->elements[nelem+i].keyname);
			if (result != ISC_R_SUCCESS)
				return result;
		}

		/* reverse sense of positives if this is a negative acl */
		if (!pos && source->elements[i].negative == ISC_FALSE) {
			dest->elements[nelem + i].negative = ISC_TRUE;
		} else {
			dest->elements[nelem + i].negative =
				source->elements[i].negative;
		}
	}

	/*
	 * Merge the iptables.  Make sure the destination ACL's
	 * node_count value is set correctly afterward.
	 */
	nodes = max_node + dest->node_count;
	result = dns_iptable_merge(dest->iptable, source->iptable, pos);
	if (result != ISC_R_SUCCESS)
		return (result);
	if (nodes > dest->node_count)
		dest->node_count = nodes;

	return (ISC_R_SUCCESS);
}

/*
 * Like dns_acl_match, but matches against the single ACL element 'e'
 * rather than a complete ACL, and returns ISC_TRUE iff it matched.
 *
 * To determine whether the match was positive or negative, the
 * caller should examine e->negative.  Since the element 'e' may be
 * a reference to a named ACL or a nested ACL, a matching element
 * returned through 'matchelt' is not necessarily 'e' itself.
 */
isc_boolean_t
dns_aclelement_match(const isc_netaddr_t *reqaddr,
		     const dns_name_t *reqsigner,
		     const dns_aclelement_t *e,
		     const dns_aclenv_t *env,
		     const dns_aclelement_t **matchelt)
{
	dns_acl_t *inner = NULL;
	int indirectmatch;
	isc_result_t result;
#ifdef HAVE_GEOIP
	uint32_t ipnum = 0;
#ifdef HAVE_GEOIP_V6
	const geoipv6_t *ipnum6 = NULL;
#ifdef DEBUG_GEOIP
	/* Use longest address type to size the buffer */
	char ipstr[INET6_ADDRSTRLEN+1] = "";
#endif
#else /* HAVE_GEOIP_V6 */
#ifdef DEBUG_GEOIP
	char ipstr[INET_ADDRSTRLEN+1] = "";
#endif
#endif /* HAVE_GEOIP_V6 */

	switch ( reqaddr->family ) {
	case AF_INET:
		ipnum = ntohl(reqaddr->type.in.s_addr);
#ifdef DEBUG_GEOIP
		inet_ntop(AF_INET, &reqaddr->type.in, ipstr, INET_ADDRSTRLEN);
#endif
		break;
#ifdef HAVE_GEOIP_V6
	case AF_INET6:
		ipnum6 = &reqaddr->type.in6;
#ifdef DEBUG_GEOIP
		inet_ntop(AF_INET6, &reqaddr->type.in6, ipstr, INET6_ADDRSTRLEN);
#endif
		break;
#endif
	}
	if ( !ipnum )
		return(ISC_FALSE);
#ifdef HAVE_GEOIP_V6
	if ( !ipnum && !ipnum6 )
		return(ISC_FALSE);
#endif
#endif /* HAVE_GEOIP */

	switch (e->type) {
	case dns_aclelementtype_keyname:
		if (reqsigner != NULL &&
		    dns_name_equal(reqsigner, &e->keyname)) {
			if (matchelt != NULL)
				*matchelt = e;
			return (ISC_TRUE);
		} else {
			return (ISC_FALSE);
		}

	case dns_aclelementtype_nestedacl:
		inner = e->nestedacl;
		break;

#ifdef HAVE_GEOIP
	/* GeoIPRecord lookups are only performed if the previous lookup was
	 * with a different IP address than the current.
	 *
	 * This allows only a single GeoIPRecord lookup per query for an entire
	 * configuration pass, instead of a GeoIPRecord lookup for each and
	 * every instance of a geoip_* ACL.  Because of this, CityDB /may/ scale
	 * more nicely than other DBs.
	 *
	 * The mechanism consists of simple statics (prev_ipnum, prev_record)
	 * for non-threaded operation, and an unspeakably painful TLS mechanism
	 * for threaded operation.
	 */
	case dns_aclelementtype_geoip_countryDB: {
		short int georesult = 0 ;
		const char *result = (const char *)NULL ;

		if ( ( ipnum && !ns_g_geoip_countryDB )
#ifdef HAVE_GEOIP_V6
		     || ( ipnum6 && !ns_g_geoip_countryDB_v6 )
#endif
		   )
			return(ISC_FALSE);

		switch ( e->geoip_countryDB.subtype ) {
		case geoip_countryDB_country_code:
			if ( ipnum )
				result = GeoIP_country_code_by_ipnum( ns_g_geoip_countryDB, ipnum );
#ifdef HAVE_GEOIP_V6
			else if ( ipnum6 )
				result = GeoIP_country_code_by_ipnum_v6( ns_g_geoip_countryDB_v6, *ipnum6 );
#endif
			if ( result )
				georesult = ( strncasecmp( e->geoip_countryDB.country_code, result, 2 ) == 0 );
#ifdef DEBUG_GEOIP
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_countryDB_country_code compared result \"%s\" to rule \"%s\", got %d neg %d",
				ipstr,
				result, e->geoip_countryDB.country_code,
				georesult, e->negative);
#endif
			break;
		case geoip_countryDB_country_code3:
			if ( ipnum )
				result = GeoIP_country_code3_by_ipnum( ns_g_geoip_countryDB, ipnum );
#ifdef HAVE_GEOIP_V6
			else if ( ipnum6 )
				result = GeoIP_country_code3_by_ipnum_v6( ns_g_geoip_countryDB_v6, *ipnum6 );
#endif
			if ( result )
				georesult = ( strncasecmp( e->geoip_countryDB.country_code3, result, 3 ) == 0 );
#ifdef DEBUG_GEOIP
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_countryDB_country_code3 compared result \"%s\" to rule \"%s\", got %d neg %d",
				ipstr,
				result, e->geoip_countryDB.country_code3,
				georesult, e->negative);
#endif
			break;
		case geoip_countryDB_country_name:
			if ( ipnum )
				result = GeoIP_country_name_by_ipnum( ns_g_geoip_countryDB, ipnum );
#ifdef HAVE_GEOIP_V6
			else if ( ipnum6 )
				result = GeoIP_country_name_by_ipnum_v6( ns_g_geoip_countryDB_v6, *ipnum6 );
#endif
			if ( result )
				georesult = ( strcasecmp( e->geoip_countryDB.country_name, result ) == 0 );
#ifdef DEBUG_GEOIP
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_countryDB_country_name compared result \"%s\" to rule \"%s\", got %d neg %d",
				ipstr,
				result, e->geoip_countryDB.country_name,
				georesult, e->negative);
#endif
			break;
		default:
			break;
		} /* switch */
		return( georesult ? ISC_TRUE : ISC_FALSE );
	} /* case geoip_countryDB */

	case dns_aclelementtype_geoip_cityDB: {
		short int georesult = 0 ;
		const char *scratch = (const char *)NULL;
		GeoIPRecord *record = (GeoIPRecord *)NULL ;
#ifdef ISC_PLATFORM_USETHREADS
		uint32_t prev_cityDB_ipnum = get_prev_cityDB_ipnum();

		GeoIPRecord *prev_cityDB_record = (GeoIPRecord *)NULL ;

		RUNTIME_CHECK(
			isc_once_do(&prev_cityDB_ipnum_once, initialize_prev_cityDB_ipnum) == ISC_R_SUCCESS
		);
		RUNTIME_CHECK(
			isc_once_do(&prev_cityDB_record_once, initialize_prev_cityDB_record) == ISC_R_SUCCESS
		);

		prev_cityDB_record = get_prev_cityDB_record();
#else
		static uint32_t prev_cityDB_ipnum = 0 ;
		static void *prev_cityDB_record ;
#endif

		if ( !ipnum || !ns_g_geoip_cityDB )
			return( ISC_FALSE );

		if ( prev_cityDB_ipnum == ipnum )
			record = prev_cityDB_record ;
		else {
			record = GeoIP_record_by_ipnum( ns_g_geoip_cityDB, ipnum );
#ifdef ISC_PLATFORM_USETHREADS
			set_prev_cityDB_record( record );
			set_prev_cityDB_ipnum( ipnum );
#else
			prev_cityDB_record = record ;
			prev_cityDB_ipnum = ipnum ;
#endif
		}
			
		if ( record ) {
			switch ( e->geoip_cityDB.subtype ) {
			case geoip_cityDB_country_code:
				if ( record->country_code )
					georesult = ( strncasecmp( e->geoip_cityDB.country_code, record->country_code, 2 ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_country_code compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					record->country_code, e->geoip_cityDB.country_code,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_country_code3:
				if ( record->country_code3 )
					georesult = ( strncasecmp( e->geoip_cityDB.country_code3, record->country_code3, 3 ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_country_code3 compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					record->country_code3, e->geoip_cityDB.country_code3,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_region:
				if ( record->region )
					georesult = ( strncasecmp( e->geoip_cityDB.region, record->region, 2 ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_region compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					record->region, e->geoip_cityDB.region,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_region_name:
				if ( record->country_code && record->region
						&& ( scratch = GeoIP_region_name_by_code(record->country_code,record->region) ) )
					georesult = ( strcasecmp( e->geoip_cityDB.region_name, scratch ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_regionname compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					scratch, e->geoip_cityDB.region_name,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_city:
				if ( record->city )
					georesult = ( strcasecmp( e->geoip_cityDB.city, record->city ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_city compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					record->city, e->geoip_cityDB.city,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_postal_code:
				if ( record->postal_code )
					georesult = ( strcasecmp( e->geoip_cityDB.postal_code, record->postal_code ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_postal compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					record->postal_code, e->geoip_cityDB.postal_code,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_range: {
				short int lat = -1 ;
				short int lon = -1 ;
				if ( e->geoip_cityDB.lat[0] || e->geoip_cityDB.lat[1] )
					lat = ( e->geoip_cityDB.lat[0] <= record->latitude && record->latitude <= e->geoip_cityDB.lat[1] );
				if ( e->geoip_cityDB.lon[0] || e->geoip_cityDB.lon[1] )
					lon = ( e->geoip_cityDB.lon[0] <= record->longitude && record->longitude <= e->geoip_cityDB.lon[1] );
				georesult = ( lat && lon );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_range compared result %f,%f to rule %f->%f,%f->%f; got %d neg %d",
					ipstr,
					record->latitude, record->longitude,
					e->geoip_cityDB.lat[0], e->geoip_cityDB.lat[1],
					e->geoip_cityDB.lon[0], e->geoip_cityDB.lon[1],
					georesult, e->negative);
#endif
				break;
			}
			case geoip_cityDB_radius:
				georesult = (( pow((record->latitude-e->geoip_cityDB.lat[0])/e->geoip_cityDB.radius[0],2) + pow((record->longitude-e->geoip_cityDB.lon[0])/e->geoip_cityDB.radius[1],2) ) <= 1 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_radius compared result %f,%f to rule %f->%f %fx%f; got %d neg %d",
					ipstr,
					record->latitude, record->longitude,
					e->geoip_cityDB.lat[0], e->geoip_cityDB.lon[0],
					e->geoip_cityDB.radius[0], e->geoip_cityDB.radius[1],
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_metro_code:
				georesult = ( e->geoip_cityDB.metro_code == record->metro_code );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_metro compared result %d to rule %d, got %d neg %d",
					ipstr,
					record->metro_code, e->geoip_cityDB.metro_code,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_area_code:
				georesult = ( e->geoip_cityDB.area_code == record->area_code );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_area compared result %d to rule %d, got %d neg %d",
					ipstr,
					record->area_code, e->geoip_cityDB.area_code,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_continent_code:
				if ( record->continent_code )
					georesult = ( strncasecmp( e->geoip_cityDB.continent_code, record->continent_code, 2 ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_continent compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					record->continent_code, e->geoip_cityDB.continent_code,
					georesult, e->negative);
#endif
				break;
			case geoip_cityDB_timezone_code:
				if ( record->country_code && record->region
						&& ( scratch = GeoIP_time_zone_by_country_and_region( record->country_code, record->region ) ) )
					georesult = ( strcasecmp( e->geoip_cityDB.timezone_code, scratch ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_cityDB_timezone compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					scratch, e->geoip_cityDB.timezone_code,
					georesult, e->negative);
#endif
				break;
			default:
				break;
			} /* switch */
		} /* if record */
#ifdef DEBUG_GEOIP
		else
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_cityDB found no record",
				ipstr);
#endif
		return( georesult ? ISC_TRUE : ISC_FALSE );
	} /* case geoip_cityDB */

	case dns_aclelementtype_geoip_regionDB: {
		short int georesult = 0 ;
		const GeoIPRegion *record = (const GeoIPRegion *)NULL ;

		if ( !ipnum || !ns_g_geoip_regionDB )
			return(ISC_FALSE);

		if (( record = GeoIP_region_by_ipnum( ns_g_geoip_regionDB, ipnum) )) {
			switch ( e->geoip_regionDB.subtype ) {
			case geoip_regionDB_country_code:
				if ( record->country_code )
					georesult = ( strncasecmp( e->geoip_regionDB.country_code, record->country_code, 3 ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_regionDB_name compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					record->country_code, e->geoip_regionDB.country_code,
					georesult, e->negative);
#endif
				break;
			case geoip_regionDB_region:
				if ( record->region && *record->region )
					georesult = ( strncasecmp( e->geoip_regionDB.region, record->region, 3 ) == 0 );
#ifdef DEBUG_GEOIP
				isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
					DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
					"client %s: geoip_regionDB_name compared result \"%s\" to rule \"%s\", got %d neg %d",
					ipstr,
					record->region, e->geoip_regionDB.region,
					georesult, e->negative);
#endif
				break;
			default:
				break;
			} /* switch */
		} /* if record */
#ifdef DEBUG_GEOIP
		else
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_regionDB found no record",
				ipstr);
#endif
		return( georesult ? ISC_TRUE : ISC_FALSE );
	} /* case geoip_regionDB */

	case dns_aclelementtype_geoip_ispDB: {
		short int georesult = 0 ;
		const char *result = (const char *)NULL ;

		if ( !ipnum || !ns_g_geoip_ispDB )
			return(ISC_FALSE);

		switch ( e->geoip_ispDB.subtype ) {
		case geoip_ispDB_name:
			if (( result = GeoIP_name_by_ipnum( ns_g_geoip_ispDB, ipnum ) ))
				georesult = ( strcasecmp( e->geoip_ispDB.name, result ) == 0 );
#ifdef DEBUG_GEOIP
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_ispDB_name compared result \"%s\" to rule \"%s\", got %d neg %d",
				ipstr,
				result, e->geoip_ispDB.name,
				georesult, e->negative);
#endif
			break;
		default:
			break;
		} /* switch */
		return( georesult ? ISC_TRUE : ISC_FALSE );
	} /* case geoip_ispDB */

	case dns_aclelementtype_geoip_orgDB: {
		short int georesult = 0 ;
		const char *result = (const char *)NULL ;

		if ( !ipnum || !ns_g_geoip_orgDB )
			return(ISC_FALSE);

		switch ( e->geoip_orgDB.subtype ) {
		case geoip_orgDB_name:
			if (( result = GeoIP_name_by_ipnum( ns_g_geoip_orgDB, ipnum ) ))
				georesult = ( strcasecmp( e->geoip_orgDB.name, result ) == 0 );
#ifdef DEBUG_GEOIP
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_orgDB_name compared result \"%s\" to rule \"%s\", got %d neg %d",
				ipstr,
				result, e->geoip_orgDB.name,
				georesult, e->negative);
#endif
			break;
		default:
			break;
		} /* switch */
		return( georesult ? ISC_TRUE : ISC_FALSE );
	} /* case geoip_orgDB */

	case dns_aclelementtype_geoip_asDB: {
		short int georesult = 0 ;
		const char *result = (const char *)NULL ;

		if ( !ipnum || !ns_g_geoip_asDB )
			return(ISC_FALSE);

		switch ( e->geoip_asDB.subtype ) {
		case geoip_asDB_org:
			if (( result = GeoIP_org_by_ipnum( ns_g_geoip_asDB, ipnum ) ))
				georesult = ( strcasecmp( e->geoip_asDB.org, result ) == 0 );
#ifdef DEBUG_GEOIP
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_asDB_org compared result \"%s\" to rule \"%s\", got %d neg %d",
				ipstr,
				result, e->geoip_asDB.org,
				georesult, e->negative);
#endif
			break;
		default:
			break;
		} /* switch */
		return( georesult ? ISC_TRUE : ISC_FALSE );
	} /* case geoip_asDB */

	case dns_aclelementtype_geoip_netspeedDB: {
		short int georesult = 0 ;
		short int result = -1 ;

		if ( !ipnum || !ns_g_geoip_netspeedDB )
			return( ISC_FALSE );

		switch ( e->geoip_netspeedDB.subtype ) {
		case geoip_netspeedDB_id:
			result = GeoIP_id_by_ipnum( ns_g_geoip_netspeedDB, ipnum );
			georesult = ( e->geoip_netspeedDB.id == result );
#ifdef DEBUG_GEOIP
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_netspeedDB_id compared result %d to rule %d, got %d neg %d",
				ipstr,
				result, e->geoip_netspeedDB.id,
				georesult, e->negative);
#endif
			break;
		default:
			break;
		} /* switch */
		return( georesult ? ISC_TRUE : ISC_FALSE );
	} /* case geoip_netspeedDB */

	case dns_aclelementtype_geoip_domainDB: {
		short int georesult = 0 ;
		const char *result = (const char *)NULL ;

		if ( !ipnum || !ns_g_geoip_domainDB )
			return(ISC_FALSE);

		switch ( e->geoip_domainDB.subtype ) {
		case geoip_domainDB_name:
			if (( result = GeoIP_name_by_ipnum( ns_g_geoip_domainDB, ipnum ) ))
				georesult = ( strcasecmp( e->geoip_domainDB.name, result ) == 0 );
#ifdef DEBUG_GEOIP
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_NOTIFY,
				DNS_LOGMODULE_ACL, ISC_LOG_DEBUG(3),
				"client %s: geoip_domainDB_name compared result \"%s\" to rule \"%s\", got %d neg %d",
				ipstr,
				result, e->geoip_domainDB.name,
				georesult, e->negative);
#endif
			break;
		default:
			break;
		} /* switch */
		return( georesult ? ISC_TRUE : ISC_FALSE );
	} /* case geoip_domainDB */

#endif /* HAVE_GEOIP */

	case dns_aclelementtype_localhost:
		if (env == NULL || env->localhost == NULL)
			return (ISC_FALSE);
		inner = env->localhost;
		break;

	case dns_aclelementtype_localnets:
		if (env == NULL || env->localnets == NULL)
			return (ISC_FALSE);
		inner = env->localnets;
		break;

	default:
		/* Should be impossible. */
		INSIST(0);
	}

	result = dns_acl_match(reqaddr, reqsigner, inner, env,
			       &indirectmatch, matchelt);
	INSIST(result == ISC_R_SUCCESS);

	/*
	 * Treat negative matches in indirect ACLs as "no match".
	 * That way, a negated indirect ACL will never become a
	 * surprise positive match through double negation.
	 * XXXDCL this should be documented.
	 */

	if (indirectmatch > 0) {
		if (matchelt != NULL)
			*matchelt = e;
		return (ISC_TRUE);
	}

	/*
	 * A negative indirect match may have set *matchelt, but we don't
	 * want it set when we return.
	 */

	if (matchelt != NULL)
		*matchelt = NULL;

	return (ISC_FALSE);
}

void
dns_acl_attach(dns_acl_t *source, dns_acl_t **target) {
	REQUIRE(DNS_ACL_VALID(source));

	isc_refcount_increment(&source->refcount, NULL);
	*target = source;
}

static void
destroy(dns_acl_t *dacl) {
	unsigned int i;

	INSIST(!ISC_LINK_LINKED(dacl, nextincache));

	for (i = 0; i < dacl->length; i++) {
		dns_aclelement_t *de = &dacl->elements[i];
		if (de->type == dns_aclelementtype_keyname) {
			dns_name_free(&de->keyname, dacl->mctx);
		} else if (de->type == dns_aclelementtype_nestedacl) {
			dns_acl_detach(&de->nestedacl);
		}
	}
	if (dacl->elements != NULL)
		isc_mem_put(dacl->mctx, dacl->elements,
			    dacl->alloc * sizeof(dns_aclelement_t));
	if (dacl->name != NULL)
		isc_mem_free(dacl->mctx, dacl->name);
	if (dacl->iptable != NULL)
		dns_iptable_detach(&dacl->iptable);
	isc_refcount_destroy(&dacl->refcount);
	dacl->magic = 0;
	isc_mem_putanddetach(&dacl->mctx, dacl, sizeof(*dacl));
}

void
dns_acl_detach(dns_acl_t **aclp) {
	dns_acl_t *acl = *aclp;
	unsigned int refs;

	REQUIRE(DNS_ACL_VALID(acl));

	isc_refcount_decrement(&acl->refcount, &refs);
	if (refs == 0)
		destroy(acl);
	*aclp = NULL;
}


static isc_once_t	insecure_prefix_once = ISC_ONCE_INIT;
static isc_mutex_t	insecure_prefix_lock;
static isc_boolean_t	insecure_prefix_found;

static void
initialize_action(void) {
	RUNTIME_CHECK(isc_mutex_init(&insecure_prefix_lock) == ISC_R_SUCCESS);
}

/*
 * Called via isc_radix_walk() to find IP table nodes that are
 * insecure.
 */
static void
is_insecure(isc_prefix_t *prefix, void **data) {
	isc_boolean_t secure;
	int bitlen, family;

	bitlen = prefix->bitlen;
	family = prefix->family;

	/* Negated entries are always secure. */
	secure = * (isc_boolean_t *)data[ISC_IS6(family)];
	if (!secure) {
		return;
	}

	/* If loopback prefix found, return */
	switch (family) {
	case AF_INET:
		if (bitlen == 32 &&
		    htonl(prefix->add.sin.s_addr) == INADDR_LOOPBACK)
			return;
		break;
	case AF_INET6:
		if (bitlen == 128 && IN6_IS_ADDR_LOOPBACK(&prefix->add.sin6))
			return;
		break;
	default:
		break;
	}

	/* Non-negated, non-loopback */
	insecure_prefix_found = ISC_TRUE;	/* LOCKED */
	return;
}

/*
 * Return ISC_TRUE iff the acl 'a' is considered insecure, that is,
 * if it contains IP addresses other than those of the local host.
 * This is intended for applications such as printing warning
 * messages for suspect ACLs; it is not intended for making access
 * control decisions.  We make no guarantee that an ACL for which
 * this function returns ISC_FALSE is safe.
 */
isc_boolean_t
dns_acl_isinsecure(const dns_acl_t *a) {
	unsigned int i;
	isc_boolean_t insecure;

	RUNTIME_CHECK(isc_once_do(&insecure_prefix_once,
				  initialize_action) == ISC_R_SUCCESS);

	/*
	 * Walk radix tree to find out if there are any non-negated,
	 * non-loopback prefixes.
	 */
	LOCK(&insecure_prefix_lock);
	insecure_prefix_found = ISC_FALSE;
	isc_radix_process(a->iptable->radix, is_insecure);
	insecure = insecure_prefix_found;
	UNLOCK(&insecure_prefix_lock);
	if (insecure)
		return(ISC_TRUE);

	/* Now check non-radix elements */
	for (i = 0; i < a->length; i++) {
		dns_aclelement_t *e = &a->elements[i];

		/* A negated match can never be insecure. */
		if (e->negative)
			continue;

		switch (e->type) {
		case dns_aclelementtype_keyname:
		case dns_aclelementtype_localhost:
			continue;

		case dns_aclelementtype_nestedacl:
			if (dns_acl_isinsecure(e->nestedacl))
				return (ISC_TRUE);
			continue;

		case dns_aclelementtype_localnets:
			return (ISC_TRUE);

		default:
			INSIST(0);
			return (ISC_TRUE);
		}
	}

	/* No insecure elements were found. */
	return (ISC_FALSE);
}

/*
 * Initialize ACL environment, setting up localhost and localnets ACLs
 */
isc_result_t
dns_aclenv_init(isc_mem_t *mctx, dns_aclenv_t *env) {
	isc_result_t result;

	env->localhost = NULL;
	env->localnets = NULL;
	result = dns_acl_create(mctx, 0, &env->localhost);
	if (result != ISC_R_SUCCESS)
		goto cleanup_nothing;
	result = dns_acl_create(mctx, 0, &env->localnets);
	if (result != ISC_R_SUCCESS)
		goto cleanup_localhost;
	env->match_mapped = ISC_FALSE;
	return (ISC_R_SUCCESS);

 cleanup_localhost:
	dns_acl_detach(&env->localhost);
 cleanup_nothing:
	return (result);
}

void
dns_aclenv_copy(dns_aclenv_t *t, dns_aclenv_t *s) {
	dns_acl_detach(&t->localhost);
	dns_acl_attach(s->localhost, &t->localhost);
	dns_acl_detach(&t->localnets);
	dns_acl_attach(s->localnets, &t->localnets);
	t->match_mapped = s->match_mapped;
}

void
dns_aclenv_destroy(dns_aclenv_t *env) {
	dns_acl_detach(&env->localhost);
	dns_acl_detach(&env->localnets);
}
