#!/ut/bin/slua

--[[ rx CLI client

syntax: rxcmd  hostname "a shell cmd"  inputfile

  inputfile: a filepath or "-" for stdin

  hostname: a rxconf.lua filename
  
]]

local rxc = require"rxc"
local util = require "util"
local lm = require 'luamonocypher'

local r, err, msk
local rcode, rdata


local function usage()
	print[[
	
Usage:   rx  servername  command  [input file]

]]
end--usage()

if not arg[1] then 
	usage()
	os.exit(1)
end

local name = arg[1]
--~ conf = os.getenv("HOME") .. "/.rx/" .. conf
name = name .. ".conf"

local f = assert(loadfile(name))
local server = assert(f())

-- set msk
server.msk = util.hextos(server.msk)
server.mpk = util.hextos(server.mpk)
assert(server.mpk == lm.public_key(server.msk), "pk matching error")

assert(rxc.clientinit(server))

-- get current encryption key
assert(rxc.refreshkey(server))

local cmd = arg[2]

local input
local inputname = arg[3]
if inputname then input = assert(util.fget(inputname)) end

local rcode, rdata = rxc.request(server, cmd, input)
print(rdata)

if rcode > 255 then 
	print("rcode:", rcode) 
else
	os.exit(rcode) 
end


