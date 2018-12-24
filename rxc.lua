-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxc


]]

------------------------------------------------------------------------
-- tmp path adjustment
package.path = "../he/?.lua;" .. package.path

------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'
local hefs = require 'hefs'
local hezen = require 'hezen'
local hepack = require 'hepack'
local hesock = require 'hesock'

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack
local ssplit = he.split
local startswith, endswith = he.startswith, he.endswith
local pp, ppl, ppt = he.pp, he.ppl, he.ppt

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end


local function repr(x)
	return strf("%q", x) 
end

local function log(...)
	print(he.isodate():sub(10), ...)
end




------------------------------------------------------------------------
-- rxc

local rx = require 'rx'

-- server info
rxs = {}

rx.server_set_defaults(rxs)

-- bind raw address  (localhost:3090)
rxs.rawaddr = '\2\0\x0c\x12\127\0\0\1\0\0\0\0\0\0\0\0'
rxs.addr = "127.0.0.1"
rxs.port = 3090
-- bind_address = '::1'    -- for ip6 localhost

-- server master key
rxs.smk = ('k'):rep(32)

-- prepare req

req = { rx = rxs }
--~ req.reqtime = (1 << 30)|1
--~ req.nonce = ("`"):rep(16)
--~ r = rx.make_req_ecb(req, 3, "abcdef")
--~ r = rx.make_req_ecb(req, 3, nil, 10)
--~ px(req.ecb)
--~ px(req.tk)

local code, paux, pb
local rcode, rpaux, rpb
local r, msg

function test_h0()
	rcode, rpaux, rpb = rx.request(rxs, 0)
	if rcode ~= 0 then 
		print("test_h0: rcode error", 
			repr(rcode), repr(rpaux), repr(rpb))
	end
	assert(rcode==0)
	assert(rpaux==os.time())
	assert(rpb=="")
	print("test_h0:  ok")
end

function test_h1()
	rcode, rpaux, rpb = rx.request(rxs, 1)
--~ 	print(repr(rcode), repr(rpaux), repr(rpb))
	assert(rcode==0)
	assert(rpaux==0)
	local r2 = hepack.unpack(rpb)
--~ 	he.pp(r2)
	assert(r2.reqtime == os.time())
	print("test_h1:  ok")
end

function test_h2() --shell
	pb = "ls /"
--~ 	pb = "ps aux"
	rcode, rpaux, rpb = rx.request(rxs, 2, 0, pb)
--~ 	print(repr(rcode), repr(rpaux), repr(rpb))
	assert(rcode==0)
--~ 	print('rpaux', rpaux)
	assert(rpaux==0)
--~ 	print(rpb)
--~ 	print(rpb:gsub("\n", " "))
	assert(rpb:match("\nvar"))
	print("test_h2:  ok")
end

function test_h3() --lua
	pb = [[
	a = { ... }
	req = a[1]
	req.rpaux = req.paux * 3
	return "ok"
	]]
	rcode, rpaux, rpb = rx.request(rxs, 3, 9, pb)
--~ 	print(repr(rcode), repr(rpaux), repr(rpb))
	assert(rcode==0)
	assert(rpaux==27)
	assert(rpb=="ok")
	pb = [[  return nil, "some error" ]]
	rcode, rpaux, rpb = rx.request(rxs, 3, 9, pb)
--~ 	print(repr(rcode), repr(rpaux), repr(rpb))
	assert(rcode==1)
	assert(rpb=="some error")
	pb = [[  3 + return ]] --syntax error
	rcode, rpaux, rpb = rx.request(rxs, 3, 9, pb)
--~ 	print(repr(rcode), repr(rpaux), repr(rpb))
	assert(rcode==2)
	print("test_h3:  ok")
end

function test_h4()
	rcode, rpaux, rpb = rx.request(rxs, 4)
--~ 	print(repr(rcode), repr(rpaux), repr(rpb))
	assert(rcode==0)
	print("test_h4:  ok")
end

function test_h5()
	rcode, rpaux, rpb = rx.request(rxs, 5)
--~ 	print(repr(rcode), repr(rpaux), repr(rpb))
	assert(rcode==0)
	print("test_h5:  ok")
end




test_h0() --ping
test_h1() --echo req
test_h2() --shell
test_h3() --lua
--~ test_h4() -- kill server
test_h5() -- restart server


--[==[
a=5

if a == 0 then
	print(rx.request(rxs, 3, 0, "for k,v in pairs(_ENV) do print(k,he.repr(v)) end "))
--~ 	print(rx.request(rxs, 3, 0, "local a={...}; he.pp(a[1].rx) "))
--~ 	print(rx.request(rxs, 3, 0, "local a={...}; he=require'he'; he.pp(a[1].rx) "))
--~ 	print(rx.request(rxs, 3, 0, "local a={...}; print(a[1].reqtime) "))
--~ 	print(rx.request(rxs, 3, 0, "print(123) "))
elseif a == 1 then
	req = { rx = rxs }
--~ 	req.reqtime = (1 << 30)|1
	req.nonce = ("`"):rep(16)
	req.code = 2
	print(rx.request_req(req))
	rx.disp_resp(req)
elseif a == 5 then 
	print(rx.request(rxs, 5))
end

]==]

