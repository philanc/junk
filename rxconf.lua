-- rx test config

local conf = {
	-- server public address (for clients)
	addr = '127.0.0.1',
	-- bind address (for server)
	bind_addr = '127.0.0.1',
	port = 4096,
	-- master key -- never run this test config as root or remote!!
	smk = ('k'):rep(32), 
}

return conf