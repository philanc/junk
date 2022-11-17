
--[[ rx client

220706 added ping command
220829 rx17 - predefined commands
221116 rx18
  
]]

local rx = require"rx"
local util = require "util"

local strf = string.format

local f, r, err, msg
local rcode, rdata
local cmd, carg, param
local locfn, remfn  -- local and remote filenames


local function usage()
	print(rx.VERSION, [[

Usage:   
	rx  d    filename [-]
	rx  u    filename
	rx  l    [arg]
	rx  ll   [arg]
	rx  md5  [arg]
	rx  t    (server timestamp)
	rx  mem  (server used memory)
	rx  du   (server total stored file size)

]])
end--usage()

local function do_request(cmdline, content)
	-- return result or nil, errmsg
	local rcode, rdata = rx.request(cmdline, content)
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
	

if not arg[1] then 
	usage()
	os.exit(1)
end

local cmd = arg[1]


local carg = arg[2] or ""
local cmdline, content

if cmd == "t" then
	r, msg = do_request("ping")
elseif cmd == "du" then
	r, msg = do_request("du")
elseif cmd == "log" then
	r, msg = do_request("log")
elseif cmd == "mem" then
	r, msg = do_request("mem")
elseif cmd == "l" then
	cmdline = strf("ls %s", carg)
	r, msg = do_request(cmdline)
elseif cmd == "ll" then
	cmdline = strf("ll %s", carg)
	r, msg = do_request(cmdline)
elseif cmd == "md5" then
	cmdline = strf("md5 %s", carg)
	r, msg = do_request(cmdline)
elseif cmd == "d" then
	cmdline = strf("fget %s", carg)
	r, msg = do_request(cmdline)
	if r then 
		locfn = arg[3] or carg
		assert(util.fput(locfn, r))
		r = "ok"
	end
elseif cmd == "u" then
	cmdline = strf("fput %s", carg)
	content = assert(util.fget(carg))
	r, msg = do_request(cmdline, content)
	if r then 
		r = "ok"
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


