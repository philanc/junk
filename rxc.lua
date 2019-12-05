-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxc 

]]


------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks
local hezen = require 'he.zen'
local sock = require 'l5.sock'

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


function rxc.request(server, data)
	-- return rdata or nil, eno, msg
	data = data or ""
	local sso, r, eno, msg
	local len = #data
	local key = server.key
	local ehdr, edata, nl, rnd = rxcore.wrap_req(key, data)
	--
	-- connect to server
	local sockaddr = server.sockaddr 
		or sock.make_ipv4_sockaddr(server.addr, server.port)
	sso, eno = sock.connect(sockaddr)
	if not sso then return nil, eno, "connect" end
	
	-- declare local before goto to prevent
	-- "jumps into the scope of local" error
	local rlen, rdata, rrnd
	
	--
	-- send 1st nonce and header
	r, eno = sock.write(sso, nl[1] .. eqhdr)
	if not r then msg = "send header"; goto ioerror end
	-- send data
	r, eno = sock.write(sso, eqdata)
	if not r then msg = "send data"; goto ioerror end
	-- recv response header
	ehdr, eno = sock.read(sso, rxcore.HDRLEN)
	if not ehdr then msg = "recv header"; goto ioerror end
	rlen, rrnd = rxcore.unwrap_hdr(key, nl[3], ehdr)
	if not rlen then
		eno = -1
		msg = rrnd
		goto ioerror
	end
	if rrnd ~= rnd then
		eno = -2
		msg = "req and resp headers not matching"
		goto ioerror
	end
	
	-- recv resp data
	r, eno = sock.read(sso, rlen + rxcore.MACLEN)
	if not r then msg = "recv data"; goto ioerror end
	rdata, msg = unwrap_data(key, reqid, 3, r)
	if not rdata then 
		eno = -1
		msg = "unwrap rdata"
		goto ioerror 
	end
	
	do -- this do block because return MUST be the last stmt of a block
	return rdata
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
