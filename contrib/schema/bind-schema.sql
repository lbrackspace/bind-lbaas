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
    zone varchar(255) not null,
    dview varchar(32),
    ttl int,
    type varchar(8),
    host varchar(255),
    mx_priority int,
    data varchar(255),
    primary_ns varchar(255),
    resp_contact varchar(255),
    serial bigint,
    refresh int,
    retry int,
    expire int,
    minimum int,
    primary key(id)
)engine=myisam default charset=utf8;

drop table if exists data_count;
create table data_count(
    zone varchar(64) not null,
    count bigint,
    primary key(zone)
)engine=myisam default charset=utf8;
