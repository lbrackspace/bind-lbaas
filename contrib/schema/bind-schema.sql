drop table if exists xfer;
create table xfer(
    id int not null auto_increment,
    zone varchar(64) not null,
    client_ip varchar(40) not null,
    primary key(id)
)engine=myisam default charset=utf8;

drop table if exists records;
create table records(
    id int not null auto_increment,
    zone varchar(64),
    dview varchar(64),
    ttl int,
    rtype varchar(8),
    rres varchar(255),
    mx_pri int,
    rdata varchar(255),
    primary_ns varchar(255),
    email varchar(255),
    serial bigint,
    retry int,
    refresh int,
    expire int,
    minimum int,
    primary key(id)
)engine=myisame default charset=utf8;

drop table if exists data_count;
create table data_count(
    zone varchar(64) not null,
    count bigint,
    primary key(zone)
)engine=myisame default charset=utf8;
