#CF= -O2 -ftracer -funroll-loops -funsafe-loop-optimizations -ggdb -g -I. 
CF= -O0 -ggdb -g -I.

all: geoipcountry

geoiputils.o: geoiputils.c geoiputils.h
	cc $(CF) -c geoiputils.c

geoipcountry.o: geoipcountry.c geoiputils.h
	cc $(CF) -c geoipcountry.c

geoipcountry: geoiputils.o geoipcountry.o
	cc $(CF) -o geoipcountry geoipcountry.o geoiputils.o -lGeoIP

clean:
	rm geoipcountry
	rm *.o
	rm *.kdbg
