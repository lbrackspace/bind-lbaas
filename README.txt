Bind9 source code with patch to support GeoIP.

On redhat or CentOS systems install the Epel repo for GeoIP
rpm -Uvh http://download.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm

To build on CentOS of Redhat install the packages.
yum install gcc make mysql-devel openldap-devel GeoIP-devel openssl-devel \
db4-devel postgresql-devel libtool git

On An Ubuntu system install
apt-get install build-essential libmysqlclient-dev libssl-dev libdb4.8-dev \
libpq-dev libtool libpq-dev libldap2-dev geoip-database libgeoip-dev git \
autoconf


Clone the project
git clone ssh://sgit@utils.rackexp.org/home/sgit/repos/bind-lbaas



run autoConf from your ./bind-lbaas/bind directory:
cd ./bind-lbaas
autoconf

before running ./configure symlink your libdb.so.?? file to 
/usr/lib since the configure script for bind is expecting to find it there.
to find the berkely db libs there. 

Redhat6.4 or CentOS6.4:
    ln -s /usr/lib64/libdb-4.7.so /usr/lib

on Ubuntu 12.04:
    ln -s /usr/lib/x86_64-linux-gnu/libdb-4.8.so /usr/lib

Also for CentOS or RedHat be sure to tell the linker to find the MySQL
lib in /usr/lib64/mysql

export LDFLAGS="-L/usr/lib64/mysql/" 

now run configure

you may want to change --prefix to some other directory other wise
"make install" will install the libs and binaries system wide.

./configure --prefix=/opt/bind \
--sysconfdir=/opt/bind/etc/bind \
--enable-threads \
--enable-largefile \
--with-libtool \
--enable-shared \
--enable-static \
--with-openssl=/usr \
--with-gssapi=/usr \
--with-gnu-ld \
--enable-ipv6 \
--with-dlz-filesysten=yes \
--with-dlz-bdb=yes \
--with-dlz-mysql=yes \
--with-dlz-postgres=yes \
--with-dlz-ldap=yes \
--with-geoip=/usr \
--with-geoip-debug


build the source code
make

