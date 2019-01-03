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

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end


------------------------------------------------------------------------
-- common rx utilities

local rx = require "rx"

------------------------------------------------------------------------
-- client functions

local function send_request(req)
	local r, errmsg
	req.server, errmsg = hesock.connect(req.rxs.rawaddr)
	if not req.server then 
		return nil, errmsg
	end
	r = rx.wrap_req(req)
	r, errmsg = req.server:write(req.ecb)
	if not r then 
		return nil, "cannot send ecb " .. repr(errmsg)
	end
	if req.ep1 then 
		r, errmsg = req.server:write(req.ep1)
		if not r then 
			return nil, "cannot send ep1 " .. repr(errmsg)
		end
	end
	if req.ep2 then 
		r, errmsg = req.server:write(req.ep2)
		if not r then 
			return nil, "cannot send ep2 " .. repr(errmsg)
		end
	end
	return true
end --send_request

local function read_response(req)
	local cb, ercb, rcb, erpb, rpb, r, errmsg
	ercb, errmsg = req.server:read(rx.ERCBLEN)
	if not ercb then
		return nil, "read ercb error " .. repr(errmsg)
	end
	if #ercb < rx.ERCBLEN then
		errmsg = "read " .. repr(#ercb) .. " bytes"
		return nil, "read ercb error " .. repr(errmsg)
	end
	r, errmsg = rx.unwrap_resp_cb(req, ercb)
	if not r then
		return nil, "unwrap_resp_cb error " .. repr(errmsg)
	end
	-- now read rpb if any
	if req.rpblen > 0 then 
		local erpblen = req.rpblen + rx.MACLEN
		erpb, errmsg = req.server:read(erpblen)
		if (not erpb) or #erpb < erpblen then
			return nil, "cannot read erpb " .. repr(errmsg)
		end
		r, errmsg = rx.unwrap_resp_pb(req, erpb)
		if not r then
			return nil, "unwrap_resp_pb error"
		end
	end
	return req
end --read_resp()

------------------------------------------------------------------------
-- rxc module and functions

local rxc = {}


function rxc.request_req(req)
	-- send a pre-initialized request and read response
	-- allows to test specific params (reqtime, nonce, ...)
	local r, errmsg
	r, errmsg = send_request(req)
	if not r then
		return nil, errmsg
	end
	r, errmsg = read_response(req)
	if not r then
		return nil, errmsg
	end
	return req
end --request_req()

function rxc.request(rxs, p1, p2)
	local r, errmsg
	local req = { 
		rxs = rxs,
		p1 = p1 or "", 
		p2 = p2 or "", 
		rpb = "",
	}
	r, errmsg = rxc.request_req(req)
	if not r then 
		return nil, errmsg
	end
	return req.rcode, req.rpb
end --request()

------------------------------------------------------------------------
-- remote execution commands

function rxc.run_basic_shell(rxs, sh)
	-- run a simple shell command with no stdin
	-- stdout is returned  
	-- (use 2>&1 to also get stderr)
	--
	local luacmd = "return rxd.shell([===[" .. sh .. "]===])"
	local rcode, rpb = rxc.request(rxs, luacmd, "")
	return rcode, rpb
end

function rxc.run_basic_lua(rxs, lua, p2)
	-- run a lua chunk
	-- a local 'req' is defined for the chunk.
	-- the chunk should return one value or nil, err
	-- this function returns tostring(value) or nil, err
	-- p2 is an optional string (defaults to "").
	-- p2 can be accessed in the chunk as req.p2
	--
	local luacmd = "local req=({...})[1]; " .. lua
	local rcode, rpb = rxc.request(rxs, luacmd, p2)
	if not rcode or rcode > 0 then 
		-- rcode==nil: connection/protocol error
		-- rcode==1: the lua chunk returned nil, err (rpb=err)
		return nil, rpb 
	end
	return rpb
end

------------------------------------------------------------------------
-- return module

return rxc
