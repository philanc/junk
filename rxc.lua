-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxc 

]]


------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks
local hezen = require 'hezen'
local hesock = require 'hesock'

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack

local traceback = require("debug").traceback

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end


------------------------------------------------------------------------
-- common rx utilities

local rxcore = require "rxcore"




------------------------------------------------------------------------
-- client functions



local function connect(server)
	local req = {}
	req.sockaddr = server.sockaddr 
		or hesock.make_ipv4_sockaddr(server.addr, server.port)
	req.state = "connect"
	req.sso = assert(hesock.connect(req.sockaddr))
	req.key = assert(server.key and #server.key == rxcore.KEYLEN,
			"server key invalid or empty")
	return req
end
	
local function send_request(req, code, arg, data)
	local reqid, eqhdr, eqdata = rxcore.wrap_req(req.key, code, arg, data)
	req.reqid = reqid
	req.state = "send req hdr"
	assert(req.sso:write(eqhdr))
	if eqdata then 
		req.state = "send req data"
		assert(req.sso:write(eqdata)) 
	end
	return true
end

local function read_response(req)
	req.state = "read resp hdr"
	local eqhdr = assert(req.sso:read(rxcore.HDRLEN))
	assert(#eqhdr == rxcore.HDRLEN, "invalid header")
	local reqid, len, code, arg = assert(rxcore.unwrap_rhdr(req.key, erhdr))
	local erdata, rdata
	if len > 0 then
		req.state = "read rdata" 
		erdata = assert(req.sso:read(len))
		rdata = assert(unwrap_rdata(req.key, reqid, erdata)
	end
	return code, arg, rdata
end

------------------------------------------------------------------------
-- rxc module and functions

local rxc = {}


function rxc.request_do(server, code, arg, data)
	-- send a request and get a response
	-- return rcode, rarg, rdata or raise an error
	local req = connect(server)
	send_request(req, code, arg, data)
	return read_response(req)
end --request_req()

function rxc.request(server, code, arg, data)
	-- send a request and read a response
	local req = connect(server)
	local ok, status, resp
	if req.debug then 
		ok, status, resp = xpcall(rxc.request_req, 
			traceback, req, cmd, data)
	else
		ok, status, resp = pcall(rxc.request_req, req, cmd, data)
	end
	if not ok then 
		-- status is the error message
		resp = tostring(rxc.state) .. ":: " .. status
		status = nil
	end
--~ 	print(req)
	if req.sso then 
		req.sso:close()
	end
	return status, resp
end --request()

------------------------------------------------------------------------
-- remote execution commands

function rxc.lua(rxs, luacmd, p2)
	-- run a lua chunk
	-- (the server defines a local 'req' in the chunk)
	-- the chunk should return one value or nil, err
	-- this function returns tostring(value) or nil, err
	-- p2 is an optional string (defaults to "").
	-- p2 can be accessed in the chunk as req.p2
	--
	local rcode, rpb = rxc.request(rxs, "lua: " .. luacmd, p2)
	if not rcode or rcode > 0 then 
		-- rcode==nil: connection/protocol error
		-- rcode==1: the lua chunk returned nil, err (rpb=err)
		return nil, rpb 
	end
	return rpb
end

function rxc.shell0(rxs, sh)
	-- run a raw shell command, no stdin, no NX
	-- sin is the optional content of stdin for the command
	-- stdout is returned  
	-- (use 2>&1 to also get stderr)
	--
	local cmd = "sh0: " .. sh
	local rcode, rpb = rxc.request(rxs, cmd, "")
	if not rcode then return nil, rpb end
	return rpb, rcode  -- result, exitcode (as he.shell)
end

function rxc.shell(rxs, sh, sin)
	-- run a simple shell command
	-- sin is the optional content of stdin for the command
	-- stdout is returned  
	-- (use 2>&1 to also get stderr)
	--
	sin = sin or ""
	local cmd = "sh: " .. sh
	local rcode, rpb = rxc.request(rxs, cmd, sin)
	if not rcode then return nil, rpb end --connection error
	return rpb, rcode  -- result, exitcode (as he.shell)
end

function rxc.file_upload(rxs, fname, content)
	local cmd = "uld: " .. fname
	local rcode, rpb = rxc.request(rxs, cmd, content)
	if not rcode or rcode > 0 then
		return nil, rpb --connection or function error
	end
	return true
end

function rxc.file_download(rxs, fname)
	local cmd = "dld: " .. fname
	local rcode, rpb = rxc.request(rxs, cmd)
	if not rcode or rcode > 0 then
		return nil, rpb --connection or function error
	end
	return rpb
end

------------------------------------------------------------------------
-- load config file (can be used both by server and client

rxc.load_rxd_config = rxcore.load_rxd_config


	
------------------------------------------------------------------------
-- return module

return rxc
