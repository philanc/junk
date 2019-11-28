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

local rxc = {}  -- the rxc module


function rxc.request(server, code, arg, data)
	-- return reqid, rcode, rarg, rdata or nil, eno, msg
	data = data or ""
	arg = arg or 0
	local sso, r, eno, msg
	local len = #data
	local key = server.key
	local reqid, eqhdr, eqdata = rxcore.wrap_req(key, arg, data)
	-- here
	--   - eqhdr includes the nonce prefix: #eqhdr = NONCELEN + HDRLEN
	--   - if data is empty, eqdata is nil.
	--
	-- connect to server
	local sockaddr = server.sockaddr 
		or hesock.make_ipv4_sockaddr(server.addr, server.port)
	sso, eno = sock.connect(sockaddr)
	if not sso then return nil, eno, "connect" end
	
	-- declare local before goto to prevent
	-- "jumps into the scope of local" error
	local rreqid, ctr, rlen, rcode, rarg, rdata
	
	--
	-- send header
	r, eno = sock.write(sso, nonce + eqhdr)
	if not r then msg = "send header"; goto ioerror end
	-- send data if any
	if eqdata then 
		r, eno = sock.write(sso, eqdata)
		if not r then msg = "send data"; goto ioerror end
	end
	-- recv response header
	r, eno = sock.read(sso, rxcore.HDRLEN)
	if not r then msg = "recv header"; goto ioerror end
	rreqid, ctr, rlen, rcode, rarg = rxcore.unwrap_hdr(key, r)
	if not rreqid then
		eno = ctr
		msg = rlen
		goto ioerror
	end
	assert(ctr == 2 and rreqid == reqid, "invalid resp header")
	--
	-- recv resp data if any
	if rlen > 0 then 
		r, eno = sock.read(sso, rlen)
		if not r then msg = "recv data"; goto ioerror end
		rdata, eno = unwrap_data(key, reqid, 3, r)
		if not rdata then msg = "unwrap rdata"; goto ioerror end
	end
	
	do -- this do block because return MUST be the last stmt of a block
	return requid, rcode, rarg, rdata
	end
	
	::ioerror::
	sock.close(sso)
	return nil, eno, msg
end




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
