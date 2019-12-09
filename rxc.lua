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
local hepack = require 'he.pack'

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack
local hpack, hunpack = hepack.pack, hepack.unpack

local traceback = require("debug").traceback

local ppp=print


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


function rxc.request(server, reqt)
	-- return rt or nil, eno, msg
	-- reqt is the request table
	-- rt is the response table
	data = hpack(reqt)
	local sso, r, eno, msg
	local len = #data
	local key = server.key
	local ehdr, edata, nl = rxcore.wrap_req(key, data)
	--
	-- connect to server
	local sockaddr = server.sockaddr 
		or sock.sockaddr(server.addr, server.port)
	sso, eno = sock.sconnect(sockaddr)
	if not sso then return nil, eno, "connect" end
	
	-- declare local before goto to prevent
	-- "jumps into the scope of local" error
	local rlen, rdata, rt
	
	--
	-- send 1st nonce and header
	r, eno = sock.write(sso, nl[1] .. ehdr)
	if not r then msg = "send header"; goto ioerror end
	-- send data
	r, eno = sock.write(sso, edata)
	if not r then msg = "send data"; goto ioerror end
	-- recv response header
	ehdr, eno = sock.read(sso, rxcore.HDRLEN)
	if not ehdr then msg = "recv header"; goto ioerror end
	rlen, msg= rxcore.unwrap_hdr(key, nl[3], ehdr)
	if not rlen then
		eno = -1
		goto ioerror
	end
	
	-- recv resp data
	edata, eno = sock.read(sso, rlen + rxcore.MACLEN)
	if not edata then msg = "recv data"; goto ioerror end
	rdata, msg = rxcore.unwrap_data(key, nl[4], edata)
	if not rdata then 
		eno = -1
		msg = "unwrap rdata"
		goto ioerror 
	end
	rt, msg = hunpack(rdata)

	do -- this do block because return MUST be the last stmt of a block
	return rt, msg
	end
	
	::ioerror::
	sock.close(sso)
	return nil, eno, msg
end

------------------------------------------------------------------------
-- remote execution commands

function rxc.lua(server, luacmd, reqt)
	-- run a lua chunk in the server environment (beware!!)
	-- rqt is the request table. if not provided it is created.
	-- it is serialized and passed to the lua chunk on the server.
	-- the chunk should return a response table
	--
	reqt = reqt or {}
	reqt.lua = luacmd
	local rt, eno, msg = rxc.request(server, reqt)
	if not rt then 
		msg = strf("rx error %s (%s)", tostring(eno), tostring(msg))
		return {ok=false, errmsg=msg}
	end
--~ 	print("RT="); he.pp(rt)
	return rt
end

function rxc.sh(server, shcmd)
	local reqt = {shcmd = shcmd, }
	luacmd = [[
		local reqt = ...
		require'hei'
		local rt = {}
		local cmd = reqt.shcmd
		local fh, msg = io.popen(cmd)
		if not fh then return {errmsg = msg} end
		local content = fh:read("a")
		local r, exit, status = fh:close()
		rt.content = content
		-- same convention as he.shell: return exitcode or
		-- signal number + 128
		rt.status = (exit=='signal' and status+128 or status)
		return rt
		]]
	local rt, msg
	rt = rxc.lua(server, luacmd, reqt)
	return rt.content, rt.errmsg
end --sh()	

function rxc.download(server, filename)
	local reqt = {}
	reqt.filename = filename
	cmd = [[
		local reqt = ...
		require'hei'
		local rt = {}
		local r, msg = he.fget(filename)
		if not r then
			rt.ok = false
			rt.errmsg = msg
		else 
			rt.ok = true
			rt.content = t
		end
		return rt
		]]
	local rt, msg
	rt = rxc.lua(server, cmd, reqt)
	return rt.content, rt.errmsg
end --download()


--[==[
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

-- ]==]
	
------------------------------------------------------------------------
-- return module

return rxc

