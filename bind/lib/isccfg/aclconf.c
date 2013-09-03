/*
 * Copyright (C) 2004-2012  Internet Systems Consortium, Inc. ("ISC")
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

/* $Id$ */

#include <config.h>

#include <isc/mem.h>
#include <isc/string.h>		/* Required for HP/UX (and others?) */
#include <isc/util.h>

#include <isccfg/namedconf.h>
#include <isccfg/aclconf.h>

#include <dns/acl.h>
#include <dns/iptable.h>
#include <dns/fixedname.h>
#include <dns/log.h>

#ifdef HAVE_GEOIP
#include <stdlib.h>
#include <math.h>
#endif /* HAVE_GEOIP */

#define LOOP_MAGIC ISC_MAGIC('L','O','O','P')

isc_result_t
cfg_aclconfctx_create(isc_mem_t *mctx, cfg_aclconfctx_t **ret) {
	isc_result_t result;
	cfg_aclconfctx_t *actx;

	REQUIRE(mctx != NULL);
	REQUIRE(ret != NULL && *ret == NULL);

	actx = isc_mem_get(mctx, sizeof(*actx));
	if (actx == NULL)
		return (ISC_R_NOMEMORY);

	result = isc_refcount_init(&actx->references, 1);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	actx->mctx = NULL;
	isc_mem_attach(mctx, &actx->mctx);
	ISC_LIST_INIT(actx->named_acl_cache);

	*ret = actx;
	return (ISC_R_SUCCESS);

 cleanup:
	isc_mem_put(mctx, actx, sizeof(*actx));
	return (result);
}

void
cfg_aclconfctx_attach(cfg_aclconfctx_t *src, cfg_aclconfctx_t **dest) {
	REQUIRE(src != NULL);
	REQUIRE(dest != NULL && *dest == NULL);

	isc_refcount_increment(&src->references, NULL);
	*dest = src;
}

void
cfg_aclconfctx_detach(cfg_aclconfctx_t **actxp) {
	cfg_aclconfctx_t *actx;
	dns_acl_t *dacl, *next;
	unsigned int refs;

	REQUIRE(actxp != NULL && *actxp != NULL);

	actx = *actxp;

	isc_refcount_decrement(&actx->references, &refs);
	if (refs == 0) {
		for (dacl = ISC_LIST_HEAD(actx->named_acl_cache);
		     dacl != NULL;
		     dacl = next)
		{
			next = ISC_LIST_NEXT(dacl, nextincache);
			ISC_LIST_UNLINK(actx->named_acl_cache, dacl,
					nextincache);
			dns_acl_detach(&dacl);
		}
		isc_mem_putanddetach(&actx->mctx, actx, sizeof(*actx));
	}

	*actxp = NULL;
}

/*
 * Find the definition of the named acl whose name is "name".
 */
static isc_result_t
get_acl_def(const cfg_obj_t *cctx, const char *name, const cfg_obj_t **ret) {
	isc_result_t result;
	const cfg_obj_t *acls = NULL;
	const cfg_listelt_t *elt;

	result = cfg_map_get(cctx, "acl", &acls);
	if (result != ISC_R_SUCCESS)
		return (result);
	for (elt = cfg_list_first(acls);
	     elt != NULL;
	     elt = cfg_list_next(elt)) {
		const cfg_obj_t *acl = cfg_listelt_value(elt);
		const char *aclname = cfg_obj_asstring(cfg_tuple_get(acl, "name"));
		if (strcasecmp(aclname, name) == 0) {
			if (ret != NULL) {
				*ret = cfg_tuple_get(acl, "value");
			}
			return (ISC_R_SUCCESS);
		}
	}
	return (ISC_R_NOTFOUND);
}

static isc_result_t
convert_named_acl(const cfg_obj_t *nameobj, const cfg_obj_t *cctx,
		  isc_log_t *lctx, cfg_aclconfctx_t *ctx,
		  isc_mem_t *mctx, unsigned int nest_level,
		  dns_acl_t **target)
{
	isc_result_t result;
	const cfg_obj_t *cacl = NULL;
	dns_acl_t *dacl;
	dns_acl_t loop;
	const char *aclname = cfg_obj_asstring(nameobj);

	/* Look for an already-converted version. */
	for (dacl = ISC_LIST_HEAD(ctx->named_acl_cache);
	     dacl != NULL;
	     dacl = ISC_LIST_NEXT(dacl, nextincache))
	{
		if (strcasecmp(aclname, dacl->name) == 0) {
			if (ISC_MAGIC_VALID(dacl, LOOP_MAGIC)) {
				cfg_obj_log(nameobj, lctx, ISC_LOG_ERROR,
					    "acl loop detected: %s", aclname);
				return (ISC_R_FAILURE);
			}
			dns_acl_attach(dacl, target);
			return (ISC_R_SUCCESS);
		}
	}
	/* Not yet converted.  Convert now. */
	result = get_acl_def(cctx, aclname, &cacl);
	if (result != ISC_R_SUCCESS) {
		cfg_obj_log(nameobj, lctx, ISC_LOG_WARNING,
			    "undefined ACL '%s'", aclname);
		return (result);
	}
	/*
	 * Add a loop detection element.
	 */
	memset(&loop, 0, sizeof(loop));
	ISC_LINK_INIT(&loop, nextincache);
	DE_CONST(aclname, loop.name);
	loop.magic = LOOP_MAGIC;
	ISC_LIST_APPEND(ctx->named_acl_cache, &loop, nextincache);
	result = cfg_acl_fromconfig(cacl, cctx, lctx, ctx, mctx,
				    nest_level, &dacl);
	ISC_LIST_UNLINK(ctx->named_acl_cache, &loop, nextincache);
	loop.magic = 0;
	loop.name = NULL;
	if (result != ISC_R_SUCCESS)
		return (result);
	dacl->name = isc_mem_strdup(dacl->mctx, aclname);
	if (dacl->name == NULL)
		return (ISC_R_NOMEMORY);
	ISC_LIST_APPEND(ctx->named_acl_cache, dacl, nextincache);
	dns_acl_attach(dacl, target);
	return (ISC_R_SUCCESS);
}

static isc_result_t
convert_keyname(const cfg_obj_t *keyobj, isc_log_t *lctx, isc_mem_t *mctx,
		dns_name_t *dnsname)
{
	isc_result_t result;
	isc_buffer_t buf;
	dns_fixedname_t fixname;
	unsigned int keylen;
	const char *txtname = cfg_obj_asstring(keyobj);

	keylen = strlen(txtname);
	isc_buffer_constinit(&buf, txtname, keylen);
	isc_buffer_add(&buf, keylen);
	dns_fixedname_init(&fixname);
	result = dns_name_fromtext(dns_fixedname_name(&fixname), &buf,
				   dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		cfg_obj_log(keyobj, lctx, ISC_LOG_WARNING,
			    "key name '%s' is not a valid domain name",
			    txtname);
		return (result);
	}
	return (dns_name_dup(dns_fixedname_name(&fixname), mctx, dnsname));
}

/*
 * Recursively pre-parse an ACL definition to find the total number
 * of non-IP-prefix elements (localhost, localnets, key) in all nested
 * ACLs, so that the parent will have enough space allocated for the
 * elements table after all the nested ACLs have been merged in to the
 * parent.
 */
static int
count_acl_elements(const cfg_obj_t *caml, const cfg_obj_t *cctx,
		   isc_boolean_t *has_negative)
{
	const cfg_listelt_t *elt;
	const cfg_obj_t *cacl = NULL;
	isc_result_t result;
	int n = 0;

	if (has_negative != NULL)
		*has_negative = ISC_FALSE;

	for (elt = cfg_list_first(caml);
	     elt != NULL;
	     elt = cfg_list_next(elt)) {
		const cfg_obj_t *ce = cfg_listelt_value(elt);

		/* negated element; just get the value. */
		if (cfg_obj_istuple(ce)) {
			ce = cfg_tuple_get(ce, "value");
			if (has_negative != NULL)
				*has_negative = ISC_TRUE;
		}

		if (cfg_obj_istype(ce, &cfg_type_keyref)) {
			n++;
		} else if (cfg_obj_islist(ce)) {
			isc_boolean_t negative;
			n += count_acl_elements(ce, cctx, &negative);
			if (negative)
				n++;
		} else if (cfg_obj_isstring(ce)) {
			const char *name = cfg_obj_asstring(ce);
			if (strcasecmp(name, "localhost") == 0 ||
			    strcasecmp(name, "localnets") == 0) {
				n++;
#ifdef HAVE_GEOIP
			/* country_ for backwards compatibility with geodns */
			} else if (strncasecmp(name, "country_", 8) == 0 ||
			           strncasecmp(name, "geoip_", 6) == 0) {
				n++;
#endif /* HAVE_GEOIP */
			} else if (strcasecmp(name, "any") != 0 &&
				   strcasecmp(name, "none") != 0) {
				result = get_acl_def(cctx, name, &cacl);
				if (result == ISC_R_SUCCESS)
					n += count_acl_elements(cacl, cctx,
								NULL) + 1;
			}
		}
	}

	return n;
}

isc_result_t
cfg_acl_fromconfig(const cfg_obj_t *caml,
		   const cfg_obj_t *cctx,
		   isc_log_t *lctx,
		   cfg_aclconfctx_t *ctx,
		   isc_mem_t *mctx,
		   unsigned int nest_level,
		   dns_acl_t **target)
{
	isc_result_t result;
	dns_acl_t *dacl = NULL, *inneracl = NULL;
	dns_aclelement_t *de;
	const cfg_listelt_t *elt;
	dns_iptable_t *iptab;
	int new_nest_level = 0;

	if (nest_level != 0)
		new_nest_level = nest_level - 1;

	REQUIRE(target != NULL);
	REQUIRE(*target == NULL || DNS_ACL_VALID(*target));

	if (*target != NULL) {
		/*
		 * If target already points to an ACL, then we're being
		 * called recursively to configure a nested ACL.  The
		 * nested ACL's contents should just be absorbed into its
		 * parent ACL.
		 */
		dns_acl_attach(*target, &dacl);
		dns_acl_detach(target);
	} else {
		/*
		 * Need to allocate a new ACL structure.  Count the items
		 * in the ACL definition that will require space in the
		 * elements table.  (Note that if nest_level is nonzero,
		 * *everything* goes in the elements table.)
		 */
		int nelem;

		if (nest_level == 0)
			nelem = count_acl_elements(caml, cctx, NULL);
		else
			nelem = cfg_list_length(caml, ISC_FALSE);

		result = dns_acl_create(mctx, nelem, &dacl);
		if (result != ISC_R_SUCCESS)
			return (result);
	}

	de = dacl->elements;
	for (elt = cfg_list_first(caml);
	     elt != NULL;
	     elt = cfg_list_next(elt)) {
		const cfg_obj_t *ce = cfg_listelt_value(elt);
		isc_boolean_t	neg;

		if (cfg_obj_istuple(ce)) {
			/* This must be a negated element. */
			ce = cfg_tuple_get(ce, "value");
			neg = ISC_TRUE;
			dacl->has_negatives = ISC_TRUE;
		} else
			neg = ISC_FALSE;

		/*
		 * If nest_level is nonzero, then every element is
		 * to be stored as a separate, nested ACL rather than
		 * merged into the main iptable.
		 */
		iptab = dacl->iptable;

		if (nest_level != 0) {
			result = dns_acl_create(mctx,
						cfg_list_length(ce, ISC_FALSE),
						&de->nestedacl);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
			iptab = de->nestedacl->iptable;
		}

		if (cfg_obj_isnetprefix(ce)) {
			/* Network prefix */
			isc_netaddr_t	addr;
			unsigned int	bitlen;

			cfg_obj_asnetprefix(ce, &addr, &bitlen);

			/*
			 * If nesting ACLs (nest_level != 0), we negate
			 * the nestedacl element, not the iptable entry.
			 */
			result = dns_iptable_addprefix(iptab, &addr, bitlen,
					      ISC_TF(nest_level != 0 || !neg));
			if (result != ISC_R_SUCCESS)
				goto cleanup;

			if (nest_level > 0) {
				de->type = dns_aclelementtype_nestedacl;
				de->negative = neg;
			} else
				continue;
		} else if (cfg_obj_islist(ce)) {
			/*
			 * If we're nesting ACLs, put the nested
			 * ACL onto the elements list; otherwise
			 * merge it into *this* ACL.  We nest ACLs
			 * in two cases: 1) sortlist, 2) if the
			 * nested ACL contains negated members.
			 */
			if (inneracl != NULL)
				dns_acl_detach(&inneracl);
			result = cfg_acl_fromconfig(ce, cctx, lctx,
						    ctx, mctx, new_nest_level,
						    &inneracl);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
nested_acl:
			if (nest_level > 0 || inneracl->has_negatives) {
				de->type = dns_aclelementtype_nestedacl;
				de->negative = neg;
				if (de->nestedacl != NULL)
					dns_acl_detach(&de->nestedacl);
				dns_acl_attach(inneracl,
					       &de->nestedacl);
				dns_acl_detach(&inneracl);
				/* Fall through. */
			} else {
				dns_acl_merge(dacl, inneracl,
					      ISC_TF(!neg));
				de += inneracl->length;  /* elements added */
				dns_acl_detach(&inneracl);
				continue;
			}
		} else if (cfg_obj_istype(ce, &cfg_type_keyref)) {
			/* Key name. */
			de->type = dns_aclelementtype_keyname;
			de->negative = neg;
			dns_name_init(&de->keyname, NULL);
			result = convert_keyname(ce, lctx, mctx,
						 &de->keyname);
			if (result != ISC_R_SUCCESS)
				goto cleanup;
		} else if (cfg_obj_isstring(ce)) {
			/* ACL name. */
			const char *name = cfg_obj_asstring(ce);
			if (strcasecmp(name, "any") == 0) {
				/* Iptable entry with zero bit length. */
				result = dns_iptable_addprefix(iptab, NULL, 0,
					      ISC_TF(nest_level != 0 || !neg));
				if (result != ISC_R_SUCCESS)
					goto cleanup;

				if (nest_level != 0) {
					de->type = dns_aclelementtype_nestedacl;
					de->negative = neg;
				} else
					continue;
			} else if (strcasecmp(name, "none") == 0) {
				/* none == !any */
				/*
				 * We don't unconditional set
				 * dacl->has_negatives and
				 * de->negative to true so we can handle
				 * "!none;".
				 */
				result = dns_iptable_addprefix(iptab, NULL, 0,
					      ISC_TF(nest_level != 0 || neg));
				if (result != ISC_R_SUCCESS)
					goto cleanup;

				if (!neg)
					dacl->has_negatives = !neg;

				if (nest_level != 0) {
					de->type = dns_aclelementtype_nestedacl;
					de->negative = !neg;
				} else
					continue;
#ifdef HAVE_GEOIP
			} else if (strncasecmp(name, "country_", 8) == 0) {
				if (strlen(name+8) == 2) {
					de->geoip_countryDB.subtype = geoip_countryDB_country_code ;
					strncpy( de->geoip_countryDB.country_code, name+8, 2 );
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP Country DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_countryDB;
				de->negative = neg;
			} /* country_XX (backwards compatibility) */
			else if (strncasecmp(name, "geoip_countryDB_", 16) == 0) {
				const char *noff = name+16 ;

				if ((strncasecmp(noff, "country_", 8) == 0) && (strlen(noff+8) == 2)) {
					de->geoip_countryDB.subtype = geoip_countryDB_country_code ;
					strncpy( de->geoip_countryDB.country_code, noff+8, 2 );
				} else if ((strncasecmp(noff, "country3_", 9) == 0) && (strlen(noff+9) == 3)) {
					de->geoip_countryDB.subtype = geoip_countryDB_country_code3 ;
					strncpy( de->geoip_countryDB.country_code3, noff+9, 3 );
				} else if (strncasecmp(noff, "country_name_", 13) == 0) {
					unsigned int c ;

					de->geoip_countryDB.subtype = geoip_countryDB_country_name ;
					strncpy( de->geoip_countryDB.country_name, noff+13, 255 );
					de->geoip_countryDB.country_name[255] = '\0' ;
					for ( c=0 ; c < strlen(de->geoip_countryDB.country_name) ; c++ )
						if ( de->geoip_countryDB.country_name[c] == '_' )
							de->geoip_countryDB.country_name[c] = ' ';
						else if ( de->geoip_countryDB.country_name[c] == '|' )
							de->geoip_countryDB.country_name[c] = '/';
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP Country DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_countryDB;
				de->negative = neg;
			} /* geoip_countryDB_ */
			else if (strncasecmp(name, "geoip_cityDB_", 13) == 0) {
				const char *noff = name+13 ;
				int match ;
				float flowt[4] ;
				char radius_type[2+1] ;

				if ((strncasecmp(noff, "country_", 8) == 0) && (strlen(noff+8) == 2)) {
					de->geoip_cityDB.subtype = geoip_cityDB_country_code ;
					strncpy( de->geoip_cityDB.country_code, noff+8, 2 );
				} else if ((strncasecmp(noff, "country3_", 9) == 0) && (strlen(noff+9) == 3)) {
					de->geoip_cityDB.subtype = geoip_cityDB_country_code3 ;
					strncpy( de->geoip_cityDB.country_code3, noff+9, 3 );
				} else if ((strncasecmp(noff, "region_", 7) == 0) && (strlen(noff+7) == 2)) {
					de->geoip_cityDB.subtype = geoip_cityDB_region ;
					strncpy( de->geoip_cityDB.region, noff+7, 2 );
				} else if (strncasecmp(noff, "regionname_", 11) == 0) {
					unsigned int c ;

					de->geoip_cityDB.subtype = geoip_cityDB_region_name ;
					strncpy( de->geoip_cityDB.region_name, noff+11, 255 );
					de->geoip_cityDB.region_name[255] = '\0' ;
					for ( c=0 ; c < strlen(de->geoip_cityDB.region_name) ; c++ )
						if ( de->geoip_cityDB.region_name[c] == '_' )
							de->geoip_cityDB.region_name[c] = ' ';
						else if ( de->geoip_cityDB.region_name[c] == '|' )
							de->geoip_cityDB.region_name[c] = '/';
				} else if (strncasecmp(noff, "city_", 5) == 0) {
					unsigned int c ;

					de->geoip_cityDB.subtype = geoip_cityDB_city ;
					strncpy( de->geoip_cityDB.city, noff+5, 255 );
					de->geoip_cityDB.city[255] = '\0' ;
					for ( c=0 ; c < strlen(de->geoip_cityDB.city) ; c++ )
						if ( de->geoip_cityDB.city[c] == '_' )
							de->geoip_cityDB.city[c] = ' ';
						else if ( de->geoip_cityDB.city[c] == '|' )
							de->geoip_cityDB.city[c] = '/';
				} else if ((strncasecmp(noff, "postal_", 7) == 0) && (strlen(noff+7) <= 6)) {
					de->geoip_cityDB.subtype = geoip_cityDB_postal_code ;
					strncpy( de->geoip_cityDB.postal_code, noff+7, 6 );
					de->geoip_cityDB.postal_code[6] = '\0' ;
				} else if (( match = sscanf(noff, "lat_%f_lat_%f_lon_%f_lon_%f", &flowt[0], &flowt[1], &flowt[2], &flowt[3]) ) == 4 ) {
					if ( fabsf(flowt[0]) >= 90 || fabsf(flowt[1]) >= 90
							|| fabsf(flowt[2]) >= 180 || fabsf(flowt[3]) >= 180 ) {
						cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
							"GeoIP ACL includes invalid lat,lat,lon,lon: %f,%f,%f,%f", flowt[0], flowt[1], flowt[2], flowt[3] );
						result = ISC_R_FAILURE;
						goto cleanup;
					}

					if ( flowt[0] == flowt[1] || flowt[2] == flowt[3] ) {
						cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
							"GeoIP ACL includes invariant lat vs. lat or lon vs. lon: %f,%f %f,%f", flowt[0], flowt[1], flowt[2], flowt[3] );
						result = ISC_R_FAILURE;
						goto cleanup;
					}

					de->geoip_cityDB.subtype = geoip_cityDB_range ;
					de->geoip_cityDB.lat[0] = flowt[0] ;
					de->geoip_cityDB.lat[1] = flowt[1] ;
					de->geoip_cityDB.lon[0] = flowt[2] ;
					de->geoip_cityDB.lon[1] = flowt[3] ;
				} else if (( match = sscanf(noff, "lat_%f_lat_%f", &flowt[0], &flowt[1]) ) == 2 ) {
					if ( flowt[0] == flowt[1] ) {
						cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
							"GeoIP ACL includes invariant lat vs. lat: %f,%f", flowt[0], flowt[1] );
						result = ISC_R_FAILURE;
						goto cleanup;
					}

					de->geoip_cityDB.subtype = geoip_cityDB_range ;
					de->geoip_cityDB.lat[0] = flowt[0] ;
					de->geoip_cityDB.lat[1] = flowt[1] ;
					de->geoip_cityDB.lon[0] = 0.0 ;
					de->geoip_cityDB.lon[1] = 0.0 ;
				} else if (( match = sscanf(noff, "lon_%f_lon_%f", &flowt[0], &flowt[1]) ) == 2 ) {
					if ( flowt[0] == flowt[1] ) {
						cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
							"GeoIP ACL includes invariant lon vs. lon: %f,%f", flowt[0], flowt[1] );
						result = ISC_R_FAILURE;
						goto cleanup;
					}

					de->geoip_cityDB.subtype = geoip_cityDB_range ;
					de->geoip_cityDB.lon[0] = flowt[0] ;
					de->geoip_cityDB.lon[1] = flowt[1] ;
					de->geoip_cityDB.lat[0] = 0.0 ;
					de->geoip_cityDB.lat[1] = 0.0 ;
				} else if (( match = sscanf(noff, "lat_%f_lon_%f_radius_%f%2s", &flowt[0], &flowt[1], &flowt[2], radius_type) ) == 4 ) {
					float de2ra = acos(-1)/180 ;
					float factor = fabsf( cos( flowt[0] * de2ra ) );

					if ( fabsf(flowt[0]) >= 90 || fabsf(flowt[1]) >= 180 ) {
						cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
							"GeoIP ACL includes invalid lat,lon: %f,%f", flowt[0], flowt[1] );
						result = ISC_R_FAILURE;
						goto cleanup;
					}

					if ( flowt[2] <= 0 ) {
						cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
							"GeoIP ACL includes invalid radius value: %f", flowt[2] );
						result = ISC_R_FAILURE;
						goto cleanup;
					}

					if ( strncasecmp( radius_type, "mi", 2 ) == 0 ) {
						static float earth_radius_mi = 3958.761 ;
						float mi_de = earth_radius_mi * de2ra ;

						de->geoip_cityDB.radius[0] = ( flowt[2] / mi_de );
						de->geoip_cityDB.radius[1] = ( flowt[2] / mi_de ) * factor ;
					}
					else if ( strncasecmp( radius_type, "km", 2 ) == 0 ) {
						static float earth_radius_km = 6371.009 ;
						float km_de = earth_radius_km * de2ra ;

						de->geoip_cityDB.radius[0] = ( flowt[2] / km_de );
						de->geoip_cityDB.radius[1] = ( flowt[2] / km_de ) * factor ;
					}
					else if ( strncasecmp( radius_type, "de", 2 ) == 0 ) {
						de->geoip_cityDB.radius[0] = flowt[2] ;
						de->geoip_cityDB.radius[1] = flowt[2] ;
					}
					else {
						cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
							"unrecognized GeoIP ACL (need mi, km, or de): %s", name );
						result = ISC_R_FAILURE;
						goto cleanup;
					}
					de->geoip_cityDB.subtype = geoip_cityDB_radius ;
					de->geoip_cityDB.lat[0] = flowt[0] ;
					de->geoip_cityDB.lon[0] = flowt[1] ;
					de->geoip_cityDB.lat[1] = 0.0 ;
					de->geoip_cityDB.lon[1] = 0.0 ;
				} else if (strncasecmp(noff, "metro_", 6) == 0) {
					de->geoip_cityDB.subtype = geoip_cityDB_metro_code ;
					de->geoip_cityDB.metro_code = atoi( noff+6 );
				} else if (strncasecmp(noff, "area_", 5) == 0) {
					de->geoip_cityDB.subtype = geoip_cityDB_area_code ;
					de->geoip_cityDB.area_code = atoi( noff+5 );
				} else if ((strncasecmp(noff, "continent_", 10) == 0) && (strlen(noff+10) == 2)) {
					de->geoip_cityDB.subtype = geoip_cityDB_continent_code ;
					strncpy( de->geoip_cityDB.continent_code, noff+10, 2 );
				} else if (strncasecmp(noff, "timezone_", 9) == 0) {
					unsigned int c ;

					de->geoip_cityDB.subtype = geoip_cityDB_timezone_code ;
					strncpy( de->geoip_cityDB.timezone_code, noff+9, 255 );
					de->geoip_cityDB.timezone_code[255] = '\0';
					for ( c=0 ; c < strlen(de->geoip_cityDB.timezone_code) ; c++ )
						if ( de->geoip_cityDB.timezone_code[c] == '_' )
							de->geoip_cityDB.timezone_code[c] = ' ';
						else if ( de->geoip_cityDB.timezone_code[c] == '|' )
							de->geoip_cityDB.timezone_code[c] = '/';
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP City DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_cityDB;
				de->negative = neg;
			} /* geoip_cityDB_ */
			else if (strncasecmp(name, "geoip_regionDB_", 15) == 0) {
				const char *noff = name+15 ;

				if ((strncasecmp(noff, "country_", 8) == 0) && (strlen(noff+8) == 2)) {
					de->geoip_regionDB.subtype = geoip_regionDB_country_code ;
					strncpy( de->geoip_regionDB.country_code, noff+8, 2 );
				} else if ((strncasecmp(noff, "region_", 7) == 0) && (strlen(noff+7) == 2)) {
					de->geoip_regionDB.subtype = geoip_regionDB_region ;
					strncpy( de->geoip_regionDB.region, noff+7, 2 );
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP Region DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_regionDB;
				de->negative = neg;
			} /* geoip_regionDB_ */
			else if (strncasecmp(name, "geoip_ispDB_", 12) == 0) {
				const char *noff = name+12 ;

				if (strncasecmp(noff, "name_", 5) == 0) {
					unsigned int c ;

					de->geoip_ispDB.subtype = geoip_ispDB_name ;
					strncpy( de->geoip_ispDB.name, noff+5, 50 );
					de->geoip_ispDB.name[50] = '\0';
					for ( c=0 ; c < strlen(de->geoip_ispDB.name) ; c++ )
						if ( de->geoip_ispDB.name[c] == '_' )
							de->geoip_ispDB.name[c] = ' ';
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP ISP DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_ispDB;
				de->negative = neg;
			} /* geoip_ispDB_ */
			else if (strncasecmp(name, "geoip_orgDB_", 12) == 0) {
				const char *noff = name+12 ;

				if (strncasecmp(noff, "name_", 5) == 0) {
					unsigned int c ;

					de->geoip_orgDB.subtype = geoip_orgDB_name ;
					strncpy( de->geoip_orgDB.name, noff+5, 50 );
					de->geoip_orgDB.name[50] = '\0';
					for ( c=0 ; c < strlen(de->geoip_orgDB.name) ; c++ )
						if ( de->geoip_orgDB.name[c] == '_' )
							de->geoip_orgDB.name[c] = ' ';
						else if ( de->geoip_orgDB.name[c] == '|' )
							de->geoip_orgDB.name[c] = '/';
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP Organization DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_orgDB;
				de->negative = neg;
			} /* geoip_orgDB_ */
			else if (strncasecmp(name, "geoip_asDB_", 11) == 0) {
				const char *noff = name+11 ;

				if (strncasecmp(noff, "org_", 4) == 0) {
					unsigned int c ;

					de->geoip_asDB.subtype = geoip_asDB_org ;
					strncpy( de->geoip_asDB.org, noff+4, 50 );
					de->geoip_asDB.org[50] = '\0';
					for ( c=0 ; c < strlen(de->geoip_asDB.org) ; c++ )
						if ( de->geoip_asDB.org[c] == '_' )
							de->geoip_asDB.org[c] = ' ';
						else if ( de->geoip_asDB.org[c] == '|' )
							de->geoip_asDB.org[c] = '/';
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP AS DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_asDB;
				de->negative = neg;
			} /* geoip_asDB_ */
			else if (strncasecmp(name, "geoip_netspeedDB_", 17) == 0) {
				const char *noff = name+17 ;

				if (strncasecmp(noff, "id_", 3) == 0) {
					de->geoip_netspeedDB.subtype = geoip_netspeedDB_id ;
					de->geoip_netspeedDB.id = atoi( noff+3 );
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP NetSpeed DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_netspeedDB;
				de->negative = neg;
			} /* geoip_netspeedDB_ */
			else if (strncasecmp(name, "geoip_domainDB_", 15) == 0) {
				const char *noff = name+15 ;

				if (strncasecmp(noff, "name_", 5) == 0) {
					unsigned int c ;

					de->geoip_domainDB.subtype = geoip_domainDB_name ;
					strncpy( de->geoip_domainDB.name, noff+5, 255 );
					de->geoip_domainDB.name[255] = '\0';
					for ( c=0 ; c < strlen(de->geoip_domainDB.name) ; c++ )
						if ( de->geoip_domainDB.name[c] == '_' )
							de->geoip_domainDB.name[c] = ' ';
						else if ( de->geoip_domainDB.name[c] == '|' )
							de->geoip_domainDB.name[c] = '/';
				} else {
					cfg_obj_log(ce, lctx, ISC_LOG_ERROR,
						"unrecognized GeoIP Domain DB ACL: %s", name );
					result = ISC_R_FAILURE;
					goto cleanup;
				}
				de->type = dns_aclelementtype_geoip_domainDB;
				de->negative = neg;
#endif /* HAVE_GEOIP */
			} else if (strcasecmp(name, "localhost") == 0) {
				de->type = dns_aclelementtype_localhost;
				de->negative = neg;
			} else if (strcasecmp(name, "localnets") == 0) {
				de->type = dns_aclelementtype_localnets;
				de->negative = neg;
			} else {
				if (inneracl != NULL)
					dns_acl_detach(&inneracl);
				result = convert_named_acl(ce, cctx, lctx, ctx,
							   mctx, new_nest_level,
							   &inneracl);
				if (result != ISC_R_SUCCESS)
					goto cleanup;

				goto nested_acl;
			}
		} else {
			cfg_obj_log(ce, lctx, ISC_LOG_WARNING,
				    "address match list contains "
				    "unsupported element type");
			result = ISC_R_FAILURE;
			goto cleanup;
		}

		/*
		 * This should only be reached for localhost, localnets
		 * and keyname elements, and nested ACLs if nest_level is
		 * nonzero (i.e., in sortlists).
		 */
		if (de->nestedacl != NULL &&
		    de->type != dns_aclelementtype_nestedacl)
			dns_acl_detach(&de->nestedacl);

		dacl->node_count++;
		de->node_num = dacl->node_count;

		dacl->length++;
		de++;
		INSIST(dacl->length <= dacl->alloc);
	}

	dns_acl_attach(dacl, target);
	result = ISC_R_SUCCESS;

 cleanup:
	if (inneracl != NULL)
		dns_acl_detach(&inneracl);
	dns_acl_detach(&dacl);
	return (result);
}
