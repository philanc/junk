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

local function connect(ctx)
	ctx.rawaddr = ctx.rawaddr 
		or hesock.make_ipv4_sockaddr(ctx.addr, ctx.port)
	ctx.state = "connect"
	ctx.server = assert(hesock.connect(ctx.rawaddr))
	return true
end
	
local function send_request(ctx, cmd, data)
	local ehdr, ecmd, edata = rxcore.encrypt_req(ctx, cmd, data)
	ctx.state = "send req hdr"
	assert(ctx.server:write(ehdr))
	if ecmd then 
		ctx.state = "send req cmd"
		assert(ctx.server:write(ecmd))
	end
	if edata then 
		ctx.state = "send req data"
		assert(ctx.server:write(edata)) 
	end
	return true
end

local function read_response(ctx)
	ctx.state = "read resp hdr"
	local ehdr = assert(ctx.server:read(rxcore.ER_HDRLEN))
	assert(#ehdr == rxcore.ER_HDRLEN, "invalid header")
	local status, resplen = rxcore.decrypt_resphdr(ctx, ehdr)
	local resp = ""
	if resplen > 0 then
		ctx.state = "read resp"
		resp = assert(rxcore.decrypt_resp(ctx, 
			assert(ctx.server:read(resplen + rxcore.MACLEN))))
	end
	return status, resp
end

------------------------------------------------------------------------
-- rxc module and functions

local rxc = {}


function rxc.request_ctx(ctx, cmd, data)
	-- send a request with a pre-initialized context and read response
	-- allows to test specific params (reqtime, nonce, ...)
	-- return status, resp or raise an error
	connect(ctx)
	send_request(ctx, cmd, data)
	return read_response(ctx)
end --request_ctx()

function rxc.request(rxs, cmd, data)
	-- send a request and read a response
	-- rxs is the server object
	local ctx = { 
		smk = rxs.smk,
		addr = rxs.addr,
		port = rxs.port,
		debug = rxs.debug,
	}
	local ok, status, resp
	if ctx.debug then 
		ok, status, resp = xpcall(rxc.request_ctx, 
			traceback, ctx, cmd, data)
	else
		ok, status, resp = pcall(rxc.request_ctx, ctx, cmd, data)
	end
	if not ok then 
		-- status is the error message
		resp = tostring(rxc.state) .. ":: " .. status
		status = nil
	end
	ctx.server:close()
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
