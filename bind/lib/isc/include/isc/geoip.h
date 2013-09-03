#ifdef HAVE_GEOIP
#ifndef _GEOIP_H
#define _GEOIP_H

#include <GeoIP.h>
#include <GeoIPCity.h>

void geoip_init( void );

extern GeoIP * ns_g_geoip_countryDB ;		/*  1  */
extern GeoIP * ns_g_geoip_cityDB ;			/* 2&6 */
extern GeoIP * ns_g_geoip_regionDB ;		/* 3&7 */
extern GeoIP * ns_g_geoip_ispDB ;			/*  4  */
extern GeoIP * ns_g_geoip_orgDB ;			/*  5  */
/* proxyDB doesn't apply in a DNS context	 *  8  */
extern GeoIP * ns_g_geoip_asDB ;			/*  9  */
extern GeoIP * ns_g_geoip_netspeedDB ;		/* 10  */
extern GeoIP * ns_g_geoip_domainDB ;		/* 11  */
#ifdef HAVE_GEOIP_V6
extern GeoIP * ns_g_geoip_countryDB_v6 ;	/* 12  */
#endif

#endif /* !_GEOIP_H */
#endif /* HAVE_GEOIP */

