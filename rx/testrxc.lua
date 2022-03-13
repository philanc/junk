-- rx client
local rxc = require"rxc"
local util = require "util"
local lm = require 'luamonocypher'

local r, err, msk
local rcode, rdata

-- init server 

local server = {
	name = "local",
	addr = "127.0.0.1",
	port = 4096,
}

-- set test msk
msk = "COFDMMN0yh+LsyUNSgJqHate4O8y/dv6SU6/ShfU8gI="
server.msk = lm.b64decode(msk)

assert(rxc.clientinit(server))

-- get current encryption key
assert(rxc.refreshkey(server))

--send request to server
print(rxc.request(server, "	pwd	"))
print(rxc.request(server, "	date	"))

-- ask the server to stop
print(rxc.request(server, "MUSTEXIT"))

