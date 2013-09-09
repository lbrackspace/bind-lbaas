insert into xfer(zone,client_ip)values('gbork.org','0.0.0.0/0');

insert into data_count(zone,count)values('gbork.org',0);

insert into records(dview,zone,ttl,type,host,mx_priority,data,primary_ns,resp_contact,serial,refresh,retry,expire,minimum)values
('default', 'gbork.org', 300, 'SOA', 'gbork.org.', NULL, NULL, 'ns1.gbork.org.', 'root.gbork.org.', 2013010100, 10800, 7200, 604800, 300),
('default', 'gbork.org', 300, 'NS', 'gbork.org.', NULL, 'ns1.gbork.org.', NULL, NULL, NULL, NULL, NULL, NULL, NULL),
('default', 'gbork.org', 300, 'NS', 'gbork.org.', NULL, 'ns2.gbork.org.', NULL, NULL, NULL, NULL, NULL, NULL, NULL),
('default', 'gbork.org', 30, 'A', 'ns1', NULL, '50.57.49.201', NULL, NULL, NULL, NULL, NULL, NULL, NULL),
('default', 'gbork.org', 30, 'A', 'ns2', NULL, '50.57.179.5', NULL, NULL, NULL, NULL, NULL, NULL, NULL),
('default', 'gbork.org', 30, 'A', 'loopback', NULL, '127.0.0.1', NULL, NULL, NULL, NULL, NULL, NULL, NULL);
