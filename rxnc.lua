

local rx = require "rx"
local hepack = require "he.pack"

he = require 'he'  -- make he global for request chunks

local ppp=print

local traceback = require("debug").traceback

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack
local hpack, hunpack = hepack.pack, hepack.unpack

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end

local server = require "rxconf"
--~ he.pp(server)
local key = server.key

local function makereq(key, reqt)
	local data = hpack(reqt)
	local ehdr, edata, noncel = rx.wrap_req(key, data)
ppp("#ehdr, #edata", #ehdr, #edata)
	local ereq = noncel[1] .. ehdr .. edata
	return ereq, noncel
end

local function openresp(key, noncel, eresp)
	local ehdr = eresp:sub(1, rx.HDRLEN)
	local edata = eresp:sub(rx.HDRLEN + 1)
	local len, msg = rx.unwrap_hdr(key, noncel[3], ehdr)
ppp("openresp", #ehdr, len)
	if not len then return nil, msg end
	local data
	data, msg = rx.unwrap_data(key, noncel[4], edata)
	if not data then 
ppp("openresp", "unwrap_data", msg)
		return nil, msg 
	end
	local rt
	rt, msg = hunpack(data)
	if not rt then return nil, msg end
	return rt
end

local function test_01()
	local reqt = {
		a = "hello",
		lua = [[ 
		local reqt = ...
		local a = reqt.a
		local rt = {a = repr(a)}
		return rt
		]],
	}
ppp("#hpack(reqt)", #hpack(reqt))
	local ereq, noncel = makereq(key, reqt)
ppp(#ereq)
end

local function test_02()
	local reqt = {
		a = "hello",
		desc="test_02",
		lua = [[ 
		local reqt = ...
		local a = reqt.a
		he=require"he"
		local s = he.shell("ps")
		local rt = {res=s, }
		return rt
		]],
	}
	local ereq, noncel = makereq(key, reqt)
	
	-- send req / get resp with nc:
	he.fput("zzz", ereq)
	local ncline = strf("ncat -w 5 %s %d <zzz", server.addr, server.port)
	local ncline = strf("/ut/bb/nc -w 5 %s %d <zzz", 
		server.addr, server.port)
	local eresp, msg, code = he.shell(ncline)
	if not eresp then print("ncat error", msg, code) end
	local rt
	rt, msg = openresp(key, noncel, eresp)
	print(rt.res)
end


--~ test_01()
test_02()
