#ifdef HAVE_GEOIP

#include <named/log.h>
#include <isc/geoip.h>

void
geoip_init()
{
#ifdef _WIN32
	GeoIPOptions geoip_method = GEOIP_STANDARD ;
#else
	GeoIPOptions geoip_method = GEOIP_MMAP_CACHE ;
#endif
	char *geoip_db_info ;

	/* COUNTRY DB */

	if ( ns_g_geoip_countryDB )
		GeoIP_delete( ns_g_geoip_countryDB );

	if ( GeoIP_db_avail( GEOIP_COUNTRY_EDITION ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP Country DB");
		if ( !( ns_g_geoip_countryDB = GeoIP_open_type( GEOIP_COUNTRY_EDITION, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP Country DB!  "
				"geoip_countryDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_countryDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP Country DB not available");

	/* CITY DB */

	if ( ns_g_geoip_cityDB )
		GeoIP_delete( ns_g_geoip_cityDB );

	if ( GeoIP_db_avail( GEOIP_CITY_EDITION_REV1 ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP City DB Revision 1");
		if ( !( ns_g_geoip_cityDB = GeoIP_open_type( GEOIP_CITY_EDITION_REV1, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP City DB Revision 1!  "
				"geoip_cityDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_cityDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else if ( GeoIP_db_avail( GEOIP_CITY_EDITION_REV0 ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP City DB Revision 0");
		if ( !( ns_g_geoip_cityDB = GeoIP_open_type( GEOIP_CITY_EDITION_REV0, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP City DB Revision 0!  "
				"geoip_cityDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_cityDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP City DB Revision 0 or 1 not available");

	/* REGION DB */

	if ( ns_g_geoip_regionDB )
		GeoIP_delete( ns_g_geoip_regionDB );

	if ( GeoIP_db_avail( GEOIP_REGION_EDITION_REV1 ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP Region DB Revision 1");
		if ( !( ns_g_geoip_regionDB = GeoIP_open_type( GEOIP_REGION_EDITION_REV1, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP Region DB Revision 1!  "
				"geoip_regionDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_regionDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else if ( GeoIP_db_avail( GEOIP_REGION_EDITION_REV0 ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP Region DB Revision 0");
		if ( !( ns_g_geoip_regionDB = GeoIP_open_type( GEOIP_REGION_EDITION_REV0, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP Region DB Revision 0!  "
				"geoip_regionDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_regionDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP Region DB Revision 0 or 1 not available");

	/* ISP DB */

	if ( ns_g_geoip_ispDB )
		GeoIP_delete( ns_g_geoip_ispDB );

	if ( GeoIP_db_avail( GEOIP_ISP_EDITION ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP ISP DB");
		if ( !( ns_g_geoip_ispDB = GeoIP_open_type( GEOIP_ISP_EDITION, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP ISP DB!  "
				"geoip_ispDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_ispDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP ISP DB not available");

	/* ORGANIZATION DB */

	if ( ns_g_geoip_orgDB )
		GeoIP_delete( ns_g_geoip_orgDB );

	if ( GeoIP_db_avail( GEOIP_ORG_EDITION ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP Organization DB");
		if ( !( ns_g_geoip_orgDB = GeoIP_open_type( GEOIP_ORG_EDITION, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP Organization DB!  "
				"geoip_orgDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_orgDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP Organization DB not available");

	/* AS DB */

	if ( ns_g_geoip_asDB )
		GeoIP_delete( ns_g_geoip_asDB );

	if ( GeoIP_db_avail( GEOIP_ASNUM_EDITION ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP AS DB");
		if ( !( ns_g_geoip_asDB = GeoIP_open_type( GEOIP_ASNUM_EDITION, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP AS DB!  "
				"geoip_asDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_asDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP AS DB not available");

	/* NETSPEED DB */

	if ( ns_g_geoip_netspeedDB )
		GeoIP_delete( ns_g_geoip_netspeedDB );

	if ( GeoIP_db_avail( GEOIP_NETSPEED_EDITION ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP NetSpeed DB");
		if ( !( ns_g_geoip_netspeedDB = GeoIP_open_type( GEOIP_NETSPEED_EDITION, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP NetSpeed DB!  "
				"geoip_netspeedDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_netspeedDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP NetSpeed DB not available");

	/* DOMAIN DB */

	if ( ns_g_geoip_domainDB )
		GeoIP_delete( ns_g_geoip_domainDB );

	if ( GeoIP_db_avail( GEOIP_DOMAIN_EDITION ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP Domain DB");
		if ( !( ns_g_geoip_domainDB = GeoIP_open_type( GEOIP_DOMAIN_EDITION, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP Domain DB!  "
				"geoip_domainDB_ matches will silently fail.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_domainDB) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP Domain DB not available");

#ifdef HAVE_GEOIP_V6

	/* COUNTRY DB IPv6 */

	if ( ns_g_geoip_countryDB_v6 )
		GeoIP_delete( ns_g_geoip_countryDB_v6 );

	if ( GeoIP_db_avail( GEOIP_COUNTRY_EDITION_V6 ) ) {
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"Initializing GeoIP Country DB IPv6");
		if ( !( ns_g_geoip_countryDB_v6 = GeoIP_open_type( GEOIP_COUNTRY_EDITION_V6, geoip_method ) ) )
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_ERROR,
				"Failed to initialize GeoIP Country DB IPv6!  "
				"geoip_countryDB_ matches will silently fail on IPv6 addresses.");
		if (( geoip_db_info = GeoIP_database_info(ns_g_geoip_countryDB_v6) ))
			isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
				NS_LOGMODULE_SERVER, ISC_LOG_INFO,
				geoip_db_info);
	} else
		isc_log_write(ns_g_lctx, NS_LOGCATEGORY_GENERAL,
			NS_LOGMODULE_SERVER, ISC_LOG_INFO,
			"GeoIP Country DB IPv6 not available");

#endif /* HAVE_GEOIP_V6 */
} /* geoip_init() */

#endif /* HAVE_GEOIP */
