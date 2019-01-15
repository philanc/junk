
-- never run this test config as root or remote!!

-- server bind address
-- localhost, port 4096 (0x1000 => \16\0)
-- rxd.rawaddr = '\2\0\16\0\127\0\0\1\0\0\0\0\0\0\0\0'
-- (for ipv6 localhost is '::1')
rxd.bind_addr = '127.0.0.1'
rxd.port = 4096

-- server public address (not required server-side)
rxd.addr = '127.0.0.1'

-- never run this test config as root or remote!!
-- server master key
rxd.smk = ('k'):rep(32) 



