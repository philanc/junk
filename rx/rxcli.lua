
--[[ rx CLI client

syntax: rx hostname "a shell cmd"  inputfile

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
name = name .. ".conf"

local confpath = os.getenv("RXPATH") or "./"
assert((confpath:match("/$")), "rx path must end with '/'")
name = confpath .. name 

f, err = loadfile(name)
if not f then
	print("conf name:", name)
	print(err)
	os.exit(22) -- EINVAL
end
local server = assert(f())
server.confpath = confpath

-- set msk
server.msk = util.hextos(server.msk)
server.mpk = util.hextos(server.mpk)
assert(server.mpk == lm.public_key(server.msk), "pk matching error")

-- attempt to get current encryption key
server.key = util.fget(server.confpath .. server.name .. ".key")
--~ assert(rxc.refreshkey(server))

local cmd = arg[2]
if cmd == "-" then cmd = assert(util.fget("-")) end

local input
local inputname = arg[3]
if inputname then input = assert(util.fget(inputname)) end
if cmd == "rk" then
	rxc.refreshkey(server)
	util.fput(confpath .. server.name .. ".key", server.key)
	return
end
local rcode, rdata = rxc.request(server, cmd, input)

if not rcode then
	print("rx error: " .. tostring(rdata))
	os.exit(1)
elseif rcode == 0 then
	print(rdata)
else  
	print("rcode:", rcode) 
	print("rdata:", rdata) 
	if (type(rcode) == "number") and rcode <= 128 then 
		os.exit(rcode) 
	else
		os.exit(1)
	end
end


