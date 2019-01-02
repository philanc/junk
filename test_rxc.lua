-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== test rxc


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
local pp, ppl, ppt = he.pp, he.ppl, he.ppt

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end





------------------------------------------------------------------------
-- rxc

local rxc = require 'rxc'

-- server info
rxs = {}

-- bind raw address  (localhost:4096)
-- rxs.rawaddr = '\2\0\1\0\127\0\0\1\0\0\0\0\0\0\0\0'
-- bind_address = '::1'    -- for ip6 localhost

rxs.addr = "127.0.0.1"
rxs.port = 4096
rxs.rawaddr = hesock.make_ipv4_sockaddr(rxs.addr, rxs.port)
print(111, repr(rxs.rawaddr))
-- server master key
rxs.smk = ('k'):rep(32)

-- prepare req

req = { rxs = rxs }
--~ req.reqtime = (1 << 30)|1
--~ req.nonce = ("`"):rep(16)
--~ r = rx.make_req_ecb(req, 3, "abcdef")
--~ r = rx.make_req_ecb(req, 3, nil, 10)
--~ px(req.ecb)
--~ px(req.tk)

local p1, p2, cmd, lua, sh
local rcode, rpb
local r, msg, exitcode

function test_0()  -- ping
	rcode, rpb = rxc.request(rxs, "", "")
	assert(rcode==os.time())
	assert(rpb=="")
	print("test_0:  ok")
end

function test_1()  -- basic lua
	cmd = " x = 123 "  -- return nil
	rcode, rpb = rxc.request(rxs, cmd, "")
	assert(rcode==0)
	assert(rpb=="")
	cmd = "return'hello' "  -- return string
	rcode, rpb = rxc.request(rxs, cmd, "")
	assert(rcode==0)
	assert(rpb=="hello")
	cmd = " 3 + if "  -- syntax error
	rcode, rpb = rxc.request(rxs, cmd, "")
	assert(rcode==999)
	cmd = " return nil, 'some error' "  -- exec error
	rcode, rpb = rxc.request(rxs, cmd, "")
	assert(rcode==1)
	assert(rpb=="some error")
--~ 	print(rpb)
	cmd = [[ -- access req object
	a = { ... }; req = a[1]
	return req.rxs.smk
	]]
	rcode, rpb = rxc.request(rxs, cmd, "")
	assert(rcode==0)
	assert(rpb==rxs.smk)
	print("test_1:  ok")
end

function test_2()  -- basic shell
	lua = "return rxd.shell([==[%s]==])"
	sh = "ls /"
	cmd = strf(lua, sh)
	rcode, rpb = rxc.request(rxs, cmd, "")
	assert(rcode==0)
	assert(rpb:match("\nvar"))
	sh = "ls --zozo  2>&1 " -- invalid option, exitcode=2
	cmd = strf(lua, sh)
	rcode, rpb = rxc.request(rxs, cmd, "")
	assert(rcode==2)
	assert(rpb:match("unrecognized option"))
	print("test_2:  ok")
end

function test_3()  -- req in lua env 
	-- req is the first chunk argument: ({...})[1]
	cmd = "return (({...})[1])"
	rcode, rpb = rxc.request(rxs, cmd, "")
--~ 	print(111, repr(rcode), repr(rpb))
	assert(rcode==0)
--~ 	assert(rpb:match"table: 0x")
	print("test_3:  ok")
end


function test_4()  -- kill server
	cmd = "({...})[1].rxs.exitcode = 1"
	rcode, rpb = rxc.request(rxs, cmd, "")
	assert(rcode==0)
	assert(rpb=="")
	print("test_4:  ok")
end

function test_5()  -- restart server
	cmd = "({...})[1].rxs.exitcode = 0"
	rcode, rpb = rxc.request(rxs, cmd, "")
	print(111, rcode, repr(rpb))
	assert(rcode==0)
	assert(rpb=="")
	print("test_5:  ok")
end

function test_6()  -- upload / download
	cmd = [[ --upload
		req = ({...})[1]
		he.fput("./zzhello", req.p2)
	]]
	p2 = "Hello, World!"
	rcode, rpb = rxc.request(rxs, cmd, p2)
	assert(rcode==0)
	assert(rpb=="")
	cmd = [[ --download
		req = ({...})[1]
		s = he.fget("./zzhello")
		os.remove("./zzhello")
		return s
	]]
	rcode, rpb = rxc.request(rxs, cmd, "")
--~ 	print(111, repr(rcode), repr(rpb))
	assert(rcode==0)
	assert(rpb==p2)
	cmd = [[ --test removed
		req = ({...})[1]
		s, msg = he.fget("./zzhello")
		return s, msg
	]]
	rcode, rpb = rxc.request(rxs, cmd, "")
--~ 	print(111, repr(rcode), repr(rpb))
	assert(rcode==1)
	assert(rpb:match"No such file")
	print("test_6:  ok")
end



test_0() -- ping
test_1() -- basic lua
test_2() -- basic shell
test_3() -- lua env
test_5() -- restart server

hesock.msleep(2000)

test_6() -- upload / download
test_4() -- kill server



