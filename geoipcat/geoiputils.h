#include<GeoIP.h>

#define STR_SIZE 4096

#define COUNTRY_BEGIN 16776960
#define STATE_BEGIN_REV0 16700000
#define STATE_BEGIN_REV1 16000000
#define STRUCTURE_INFO_MAX_SIZE 20
#define DATABASE_INFO_MAX_SIZE 100
#define MAX_ORG_RECORD_LENGTH 300
#define US_OFFSET 1
#define CANADA_OFFSET 677
#define WORLD_OFFSET 1353
#define FIPS_RANGE 360


void _setup_segments(GeoIP * gi);
geoipv6_t _GeoIP_addr_to_num_v6(const char *addr);
unsigned int _GeoIP_seek_record_v6 (GeoIP *gi, geoipv6_t ipnum);
unsigned int _GeoIP_seek_record (GeoIP *gi, unsigned long ipnum);
unsigned long _GeoIP_addr_to_num(const char *addr);
char *_get_name_v6 (GeoIP* gi, geoipv6_t ipnum);
int _check_mtime(GeoIP *gi);
