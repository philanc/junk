
--[[ rx CLI client

220706 added ping command
220829  rx17 - predefined commands

syntax: rx hostname cmd [arg] [inputfile]

  cmd:  keyreq ping fget fput sh exit testerror

  inputfile: a filepath or "-" for stdin

  hostname: a rxconf.lua filename
  
]]

local rxc = require"rxc"
local util = require "util"
local lm = require 'luamonocypher'

local strf = string.format

local f, r, err, msg
local rcode, rdata
local cmd, carg, param
local locfn, remfn  -- local and remote filenames


local function usage()
	print[[
	
Usage:   rx  servername  x  shellcmd  
         rx  servername  d  remotefilename localfilename
         rx  servername  u  localfilename  remotefilename
         rx  servername  t  (server timestamp)
         rx  servername  e  (server exit)
         rx  servername  ee (test exit with error)
         rx  servername  k  (refresh key)
]]
end--usage()

local function do_request(server, cmd, carg, param)
	-- return result or nil, errmsg
	local rcode, rdata = rxc.request(server, cmd, carg, param)
	local r, msg
	if not rcode then
		r = nil
		msg = "rx error: " .. tostring(rdata)
	elseif rcode ~= 0 then
		r = nil
		msg = strf("rcode: %s\nrdata: %s", rcode, rdata)
	else
		r = rdata
	end
	return r, msg
end --do_request
	

if not (arg[1] and arg[2]) then 
	usage()
	os.exit(1)
end

local name = arg[1]
local server = assert(rxc.loadconf(name))

local cmd = arg[2]
--~ if cmd == "-" then cmd = assert(util.fget("-")) end

local r, err, filename, shellcmd

if not arg[2] then
	usage()
	os.exit(1)
end

if cmd == "k" then
	r, err = rxc.refreshkey(server)
	if not r then 
		print("refreshkey error", err)
		os.exit(1)
	end
	util.fput(server.confpath .. server.name .. ".key", server.key)
	return
elseif cmd == "t" then
	r, msg = do_request(server, "ping")
elseif cmd == "x" then
	carg = arg[3]
	if not carg then 
		r, msg = nil, "shell command not provided" 
	else
		r, msg = do_request(server, "sh", carg, param)
	end
elseif cmd == "e" then
	r, msg = do_request(server, "exit")
elseif cmd == "ee" then
	r, msg = do_request(server, "testerror")
elseif cmd == "d" then
	remfn = arg[3]
	locfn = arg[4]
	if not remfn then 
		r, msg = nil, "remote filename not provided"
	elseif not locfn then 
		r, msg = nil, "local filename not provided"
	else 
		r, msg = do_request(server, "fget", remfn, param)
	end
	if r then 
		assert(util.fput(locfn, r))
		r = "ok"
	end
elseif cmd == "u" then
	locfn = arg[3]
	remfn = arg[4]
	if not remfn then 
		r, msg = nil, "remote filename not provided"
	elseif not locfn then 
		r, msg = nil, "local filename not provided"
	else 
		r, msg = util.fget(locfn)
		if r then 
			r, msg = do_request(server, "fput", remfn, param)
		end
	end
else
	r = nil
	msg = strf("Unknown command: %s", cmd)
end

if not r then
	print(msg)
	os.exit(1)
else
	print(r)
end


