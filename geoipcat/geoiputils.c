#include<arpa/inet.h>
#include<sys/mman.h>
#include<netdb.h>
#include<inttypes.h>
#include<sys/types.h>
#include<unistd.h>
#include<stdio.h>
#include<GeoIP.h>
#include<geoiputils.h>

static geoipv6_t IPV6_NULL;

void _setup_segments(GeoIP * gi) {
	int i, j;
	unsigned char delim[3];
	unsigned char buf[SEGMENT_RECORD_LENGTH];

	gi->databaseSegments = NULL;

	/* default to GeoIP Country Edition */
	gi->databaseType = GEOIP_COUNTRY_EDITION;
	gi->record_length = STANDARD_RECORD_LENGTH;
	fseek(gi->GeoIPDatabase, -3l, SEEK_END);
	for (i = 0; i < STRUCTURE_INFO_MAX_SIZE; i++) {
		fread(delim, 1, 3, gi->GeoIPDatabase);
		if (delim[0] == 255 && delim[1] == 255 && delim[2] == 255) {
			fread(&gi->databaseType, 1, 1, gi->GeoIPDatabase);
			if (gi->databaseType >= 106) {
				/* backwards compatibility with databases from April 2003 and earlier */
				gi->databaseType -= 105;
			}

			if (gi->databaseType == GEOIP_REGION_EDITION_REV0) {
				/* Region Edition, pre June 2003 */
				gi->databaseSegments = malloc(sizeof(int));
				gi->databaseSegments[0] = STATE_BEGIN_REV0;
			} else if (gi->databaseType == GEOIP_REGION_EDITION_REV1) {
				/* Region Edition, post June 2003 */
				gi->databaseSegments = malloc(sizeof(int));
				gi->databaseSegments[0] = STATE_BEGIN_REV1;
			} else if (gi->databaseType == GEOIP_CITY_EDITION_REV0 ||
								 gi->databaseType == GEOIP_CITY_EDITION_REV1 ||
								 gi->databaseType == GEOIP_ORG_EDITION ||
								 gi->databaseType == GEOIP_ISP_EDITION ||
								 gi->databaseType == GEOIP_ASNUM_EDITION) {
				/* City/Org Editions have two segments, read offset of second segment */
				gi->databaseSegments = malloc(sizeof(int));
				gi->databaseSegments[0] = 0;
				fread(buf, SEGMENT_RECORD_LENGTH, 1, gi->GeoIPDatabase);
				for (j = 0; j < SEGMENT_RECORD_LENGTH; j++) {
					gi->databaseSegments[0] += (buf[j] << (j * 8));
				}
				if (gi->databaseType == GEOIP_ORG_EDITION ||
						gi->databaseType == GEOIP_ISP_EDITION)
					gi->record_length = ORG_RECORD_LENGTH;
			}
			break;
		} else {
			fseek(gi->GeoIPDatabase, -4l, SEEK_CUR);
		}
	}
	if (gi->databaseType == GEOIP_COUNTRY_EDITION ||
			gi->databaseType == GEOIP_PROXY_EDITION ||
			gi->databaseType == GEOIP_NETSPEED_EDITION ||
			gi->databaseType == GEOIP_COUNTRY_EDITION_V6 ) {
		gi->databaseSegments = malloc(sizeof(int));
		gi->databaseSegments[0] = COUNTRY_BEGIN;
	}
}



geoipv6_t _GeoIP_addr_to_num_v6(const char *addr)
{
       geoipv6_t       ipnum;
        if ( 1 == inet_pton(AF_INET6, addr, &ipnum.s6_addr[0] ) )
          return ipnum;
       return IPV6_NULL;
}

unsigned int _GeoIP_seek_record_v6 (GeoIP *gi, geoipv6_t ipnum) {
       int depth;
       char paddr[8 * 4 + 7 + 1];
       unsigned int x;
       unsigned char stack_buffer[2 * MAX_RECORD_LENGTH];
       const unsigned char *buf = (gi->cache == NULL) ? stack_buffer : NULL;
       unsigned int offset = 0;

       const unsigned char * p;
       int j;

       _check_mtime(gi);
       for (depth = 127; depth >= 0; depth--) {
               if (gi->cache == NULL && gi->index_cache == NULL) {
                       /* read from disk */
                       fseek(gi->GeoIPDatabase, (long)gi->record_length * 2 * offset, SEEK_SET);
                       fread(stack_buffer,gi->record_length,2,gi->GeoIPDatabase);
               } else if (gi->index_cache == NULL) {
                       /* simply point to record in memory */
                       buf = gi->cache + (long)gi->record_length * 2 *offset;
               } else {
                       buf = gi->index_cache + (long)gi->record_length * 2 * offset;
               }

               if (GEOIP_CHKBIT_V6(depth, ipnum.s6_addr )) {
                       /* Take the right-hand branch */
                       if ( gi->record_length == 3 ) {
                               /* Most common case is completely unrolled and uses constants. */
                               x =   (buf[3*1 + 0] << (0*8))
                                       + (buf[3*1 + 1] << (1*8))
                                       + (buf[3*1 + 2] << (2*8));

                       } else {
                               /* General case */
                               j = gi->record_length;
                               p = &buf[2*j];
                               x = 0;
                               do {
                                       x <<= 8;
                                       x += *(--p);
                               } while ( --j );
                       }

              } else {
                       /* Take the left-hand branch */
                       if ( gi->record_length == 3 ) {
                               /* Most common case is completely unrolled and uses constants. */
                               x =   (buf[3*0 + 0] << (0*8))
                                       + (buf[3*0 + 1] << (1*8))
                                       + (buf[3*0 + 2] << (2*8));
                       } else {
                               /* General case */
                               j = gi->record_length;
                               p = &buf[1*j];
                               x = 0;
                               do {
                                       x <<= 8;
                                       x += *(--p);
                               } while ( --j );
                       }
               }

               if (x >= gi->databaseSegments[0]) {
                       gi->netmask = 128 - depth;
                       return x;
               }
               offset = x;
       }

       /* shouldn't reach here */
        inet_pton(AF_INET6, &ipnum.s6_addr[0], paddr );        
       fprintf(stderr,"Error Traversing Database for ipnum = %s - Perhaps database is corrupt?\n", paddr);
       return 0;
}


unsigned long _GeoIP_addr_to_num(const char *addr)
{
        unsigned int    c, octet, t;
        unsigned long   ipnum;
        int             i = 3;

        octet = ipnum = 0;
        while ((c = *addr++)) {
                if (c == '.') {
                        if (octet > 255)
                                return 0;
                        ipnum <<= 8;
                        ipnum += octet;
                        i--;
                        octet = 0;
                } else {
                        t = octet;
                        octet <<= 3;
                        octet += t;
                        octet += t;
                        c -= '0';
                        if (c > 9)
                                return 0;
                        octet += c;
                }
        }
        if ((octet > 255) || (i != 0))
                return 0;
        ipnum <<= 8;
        return ipnum + octet;
}

unsigned int _GeoIP_seek_record (GeoIP *gi, unsigned long ipnum) {
	int depth;
	unsigned int x;
	unsigned char stack_buffer[2 * MAX_RECORD_LENGTH];
	const unsigned char *buf = (gi->cache == NULL) ? stack_buffer : NULL;
	unsigned int offset = 0;

	const unsigned char * p;
	int j;

	_check_mtime(gi);
	for (depth = 31; depth >= 0; depth--) {
		if (gi->cache == NULL && gi->index_cache == NULL) {
			/* read from disk */
			fseek(gi->GeoIPDatabase, (long)gi->record_length * 2 * offset, SEEK_SET);
			fread(stack_buffer,gi->record_length,2,gi->GeoIPDatabase);
		} else if (gi->index_cache == NULL) {
			/* simply point to record in memory */
			buf = gi->cache + (long)gi->record_length * 2 *offset;
		} else {
			buf = gi->index_cache + (long)gi->record_length * 2 * offset;
		}

		if (ipnum & (1 << depth)) {
			/* Take the right-hand branch */
			if ( gi->record_length == 3 ) {
				/* Most common case is completely unrolled and uses constants. */
				x =   (buf[3*1 + 0] << (0*8))
					+ (buf[3*1 + 1] << (1*8))
					+ (buf[3*1 + 2] << (2*8));

			} else {
				/* General case */
				j = gi->record_length;
				p = &buf[2*j];
				x = 0;
				do {
					x <<= 8;
					x += *(--p);
				} while ( --j );
			}

		} else {
			/* Take the left-hand branch */
			if ( gi->record_length == 3 ) {
				/* Most common case is completely unrolled and uses constants. */
				x =   (buf[3*0 + 0] << (0*8))
					+ (buf[3*0 + 1] << (1*8))
					+ (buf[3*0 + 2] << (2*8));
			} else {
				/* General case */
				j = gi->record_length;
				p = &buf[1*j];
				x = 0;
				do {
					x <<= 8;
					x += *(--p);
				} while ( --j );
			}
		}

		if (x >= gi->databaseSegments[0]) {
			gi->netmask = 32 - depth;
			return x;
		}
		offset = x;
	}

	/* shouldn't reach here */
	fprintf(stderr,"Error Traversing Database for ipnum = %lu - Perhaps database is corrupt?\n",ipnum);
	return 0;
}


char *_get_name_v6 (GeoIP* gi, geoipv6_t ipnum) {
  int seek_org;
  char buf[MAX_ORG_RECORD_LENGTH];
  char * org_buf, * buf_pointer;
  int record_pointer;
  size_t len;

  if (gi->databaseType != GEOIP_ORG_EDITION &&
      gi->databaseType != GEOIP_ISP_EDITION &&
      gi->databaseType != GEOIP_ASNUM_EDITION) {
    printf("Invalid database type %s, expected %s\n", GeoIPDBDescription[(int)gi->databaseType], GeoIPDBDescription[GEOIP_ORG_EDITION]);
    return NULL;
  }

  seek_org = _GeoIP_seek_record_v6(gi, ipnum);
  if (seek_org == gi->databaseSegments[0])
    return NULL;

  record_pointer = seek_org + (2 * gi->record_length - 1) * gi->databaseSegments[0];

  if (gi->cache == NULL) {
    fseek(gi->GeoIPDatabase, record_pointer, SEEK_SET);
    fread(buf, sizeof(char), MAX_ORG_RECORD_LENGTH, gi->GeoIPDatabase);
    len = sizeof(char) * (strlen(buf)+1);
    org_buf = malloc(len);
    strncpy(org_buf, buf, len);
  } else {
    buf_pointer = gi->cache + (long)record_pointer;
    len = sizeof(char) * (strlen(buf_pointer)+1);
    org_buf = malloc(len);
    strncpy(org_buf, buf_pointer, len);
  }
  return org_buf;
}

int _check_mtime(GeoIP *gi) {
	struct stat buf;
  struct timeval t;
		
	/* stat only has second granularity, so don't
	   call it more than once a second */
	gettimeofday(&t, NULL);
	if (t.tv_sec == gi->last_mtime_check){
		return 0;
	}
	gi->last_mtime_check = t.tv_sec;

  if (gi->flags & GEOIP_CHECK_CACHE) {
		if (stat(gi->file_path, &buf) != -1) {
			if (buf.st_mtime != gi->mtime) {
				/* GeoIP Database file updated */
				if (gi->flags & (GEOIP_MEMORY_CACHE | GEOIP_MMAP_CACHE)) {
				    if ( gi->flags & GEOIP_MMAP_CACHE) {
#if !defined(WIN32) && !defined(WIN64)
							/* MMAP is only avail on UNIX */
					munmap(gi->cache, gi->size);
					gi->cache = NULL;
#endif
				    } else {
					/* reload database into memory cache */
					if ((gi->cache = (unsigned char*) realloc(gi->cache, buf.st_size)) == NULL) {
						fprintf(stderr,"Out of memory when reloading %s\n",gi->file_path);
						return -1;
					}
				    }
				}
				/* refresh filehandle */
				fclose(gi->GeoIPDatabase);
				gi->GeoIPDatabase = fopen(gi->file_path,"rb");
				if (gi->GeoIPDatabase == NULL) {
					fprintf(stderr,"Error Opening file %s when reloading\n",gi->file_path);
					return -1;
				}
				gi->mtime = buf.st_mtime;
				gi->size = buf.st_size;

				if ( gi->flags & GEOIP_MMAP_CACHE) {
#if defined(WIN32) || defined(WIN64)
					fprintf(stderr, "GEOIP_MMAP_CACHE is not supported on WIN32\n");
					gi->cache = 0;
					return -1;
#else
				    gi->cache = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fileno(gi->GeoIPDatabase), 0);
				    if ( gi->cache == MAP_FAILED ) {

					    fprintf(stderr,"Error remapping file %s when reloading\n",gi->file_path);

					    gi->cache = 0;
					    return -1;
				    }
#endif
				} else if ( gi->flags & GEOIP_MEMORY_CACHE ) {
				    if (fread(gi->cache, sizeof(unsigned char), buf.st_size, gi->GeoIPDatabase) != (size_t) buf.st_size) {
					    fprintf(stderr,"Error reading file %s when reloading\n",gi->file_path);
					    return -1;
					}
				}

				if (gi->databaseSegments != NULL) {
					free(gi->databaseSegments);
					gi->databaseSegments = NULL;
				}
				_setup_segments(gi);
				if (gi->databaseSegments == NULL) {
					fprintf(stderr, "Error reading file %s -- corrupt\n", gi->file_path);
					return -1;
				}
				if (gi->flags & GEOIP_INDEX_CACHE) {                        
					gi->index_cache = (unsigned char *) realloc(gi->index_cache, sizeof(unsigned char) * ((gi->databaseSegments[0] * (long)gi->record_length * 2)));
					if (gi->index_cache != NULL) {
						fseek(gi->GeoIPDatabase, 0, SEEK_SET);
						if (fread(gi->index_cache, sizeof(unsigned char), gi->databaseSegments[0] * (long)gi->record_length * 2, gi->GeoIPDatabase) != (size_t) (gi->databaseSegments[0]*(long)gi->record_length * 2)) {
							fprintf(stderr,"Error reading file %s where reloading\n",gi->file_path);
							return -1;
						}
					}
				}
			}
		}
	}
	return 0;
}

int ipnum_range_by_ip (GeoIP* gi, unsigned long ipnum,unsigned long *ret) {
	unsigned long left_seek;
	unsigned long right_seek;
	unsigned long mask;
	int orig_netmask;
	int target_value;
	
	target_value = _GeoIP_seek_record(gi, ipnum);
	orig_netmask = GeoIP_last_netmask(gi);
	mask = 0xffffffff << ( 32 - orig_netmask );	
	left_seek = ipnum & mask;
	right_seek = left_seek + ( 0xffffffff & ~mask );

	while (left_seek != 0 
	  && target_value == _GeoIP_seek_record(gi, left_seek - 1) ) {
		
		/* Go to beginning of netblock defined by netmask */
		mask = 0xffffffff << ( 32 - GeoIP_last_netmask(gi) );
		left_seek = --left_seek & mask;
	}
        ret[0] = left_seek;

	while (right_seek != 0xffffffff
	  && target_value == _GeoIP_seek_record(gi, right_seek + 1) ) {
		
		/* Go to end of netblock defined by netmask */
		mask = 0xffffffff << ( 32 - GeoIP_last_netmask(gi) );
		right_seek = ++right_seek & mask;
		right_seek += 0xffffffff & ~mask;
	}
        ret[1] = right_seek;

	gi->netmask = orig_netmask;

	return 0;
}

int num_to_addr(unsigned long ipnum,char *ret_str){
        char *cur_str;
        int octet[4];
        int num_chars_written, i;

        cur_str = ret_str;

        for (i = 0; i<4; i++) {
                octet[3 - i] = ipnum % 256;
                ipnum >>= 8;
        }

        for (i = 0; i<4; i++) {
                num_chars_written = sprintf(cur_str, "%d", octet[i]);
                cur_str += num_chars_written;

                if (i < 3) {
                        cur_str[0] = '.';
                        cur_str++;
                }
        }
}

char *_GeoIP_num_to_addr (GeoIP* gi, unsigned long ipnum) {
        char *ret_str;
        char *cur_str;
        int octet[4];
        int num_chars_written, i;

        ret_str = malloc(sizeof(char) * 16);
        cur_str = ret_str;

        for (i = 0; i<4; i++) {
                octet[3 - i] = ipnum % 256;
                ipnum >>= 8;
        }

        for (i = 0; i<4; i++) {
                num_chars_written = sprintf(cur_str, "%d", octet[i]);
                cur_str += num_chars_written;

                if (i < 3) {
                        cur_str[0] = '.';
                        cur_str++;
                }
        }

        return ret_str;
}
