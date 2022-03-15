#!/ut/bin/slua

--[[ rx CLI client

syntax: rxcmd  hostname "a shell cmd"  inputfile

  inputfile: a filepath or "-" for stdin

  hostname: a rxconf.lua filename
  
]]

local rxc = require"rxc"
local util = require "util"
local lm = require 'luamonocypher'

local f, r, err, msk
local rcode, rdata


local function usage()
	print[[
	
Usage:   rx  servername  command  [input file]
         rx  servername  rk
]]
end--usage()

if not (arg[1] and arg[2]) then 
	usage()
	os.exit(1)
end

local name = arg[1]
--~ conf = os.getenv("HOME") .. "/.rx/" .. conf
name = name .. ".conf"

f, err = loadfile(name)
if not f then
	name = os.getenv("HOME") .. "/.rx/" .. name
	f, err = loadfile(name)
	if not f then
		print("conf name:", name)
		print(err)
		os.exit(22) -- EINVAL
	end
end
local server = assert(f())

-- set msk
server.msk = util.hextos(server.msk)
server.mpk = util.hextos(server.mpk)
assert(server.mpk == lm.public_key(server.msk), "pk matching error")

r, err = assert(rxc.clientinit(server))


-- get current encryption key
--~ assert(rxc.refreshkey(server))

local cmd = arg[2]

local input
local inputname = arg[3]
if inputname then input = assert(util.fget(inputname)) end
if cmd == "rk" then
	rxc.refreshkey(server)
	util.fput(server.name .. ".key", server.key)
	return
end
local rcode, rdata = rxc.request(server, cmd, input)
print(rdata)

if rcode > 255 then 
	print("rcode:", rcode) 
else
	os.exit(rcode) 
end


