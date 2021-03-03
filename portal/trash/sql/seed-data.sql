-- This is assuming fresh db - user insert to users has id=1.
-- user:pass for testing is portaltester@uvoo.io:DemoAppMe!987
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
-- provides: gen_random_uuid()
INSERT into users (username, password_hash, otp_enabled) values ('portaltester@uvoo.io', 'some password hash', FALSE);
INSERT into apis (name, version, url) values ('ethereum', 'v0.1.0-beta', 'https://api.uvoo.io/ethereum/');
INSERT into apis (name, version, url) values ('bitcoin', 'v0.1.0-beta', 'https://api.uvoo.io/bitcoin/');
INSERT into user_apis (api_id, user_id, monthly_requests, total_requests) values (1, 1, 0, 0);
INSERT into user_apis (api_id, user_id, monthly_requests, total_requests) values (2, 1, 0, 0);
INSERT into access_tokens (user_id, access_token, note) values ('myrandomtoken', 'ci/cd tests token');
INSERT INTO prov_client (name, token, ips) VALUES ('h-lxd1.uvoo.io', 'myuuidor random token', 'ipaddr/32')
