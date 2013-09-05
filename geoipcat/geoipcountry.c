#include<stdio.h>
#include<GeoIP.h>
#include<geoiputils.h>

int main(int argc,char **argv){
    pid_t pid;
    int i;
    char ip_lo[16];
    char ip_hi[16];
    unsigned long ip_range[2];
    unsigned int record_pos;
    unsigned long ipnum;
    const char *countryCode;
    const char *countryName;
    char *search_ip;
    int country_id;

    printf("sizeof(GeoIP) = %zi\n",sizeof(GeoIP));
    size_t tmp_size;
    tmp_size = sizeof(char)*(STR_SIZE + 1);
    GeoIP *g = NULL;
    g = GeoIP_new(GEOIP_MEMORY_CACHE);
    if(g==NULL){
        fprintf(stderr,"Error opening default database\n");
        return -1;
    }
    printf("#DB Info: %s\n",GeoIP_database_info(g));
    printf("#SEGMENT_RECORD_LENGTH=%d\n",SEGMENT_RECORD_LENGTH);
    printf("#MAX_RECORD_LENGTH=%d\n",MAX_RECORD_LENGTH);
    printf("#g->databaseSegments[0] = %d\n",g->databaseSegments[0]);
    printf("#g->recordLength = %d\n",g->record_length);
    printf("#g->size = %zi\n",g->size);
    printf("#number of known countries: %d\n",GeoIP_num_countries());
    printf("#sizeof(geoipv6_t)=%zi\n",sizeof(geoipv6_t));
    printf("#g->cache=%p\n",g->cache);
    printf("#g->index_cache=%p\n",g->index_cache);
    if(argc>=2){
        search_ip = argv[1];
        printf("#Searching for %s\n",search_ip);
        ipnum = _GeoIP_addr_to_num(search_ip);
        ipnum_range_by_ip(g,ipnum,ip_range);
        num_to_addr(ip_range[0],ip_lo);
        num_to_addr(ip_range[1],ip_hi);
        country_id = GeoIP_id_by_ipnum(g,ipnum);
        countryCode = GeoIP_country_code[country_id];
        countryName = GeoIP_country_name[country_id];
        printf("%s, %s, %s, %s\n",ip_lo,ip_hi,countryCode,countryName);
        return 0;
    }
    ipnum = 0;
    printf("Dumping all records\n");
    while(ipnum <= 0xffffffff){
        ipnum_range_by_ip(g,ipnum,ip_range);
        num_to_addr(ip_range[0],ip_lo);
        num_to_addr(ip_range[1],ip_hi);
        country_id = GeoIP_id_by_ipnum(g,ipnum);
        countryCode = GeoIP_country_code[country_id];
        countryName = GeoIP_country_name[country_id];
        printf("%s, %s, %s, %s\n",ip_lo,ip_hi,countryCode,countryName);
        ipnum = ip_range[1] + 1;
    }
    return 0;
}

