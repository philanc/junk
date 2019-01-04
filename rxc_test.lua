-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxc crude test


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
--~ print(111, repr(rxs.rawaddr))
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
	assert(rcode, "??? maybe server not started ???")
	assert(math.abs(rcode - os.time()) < 30 )
	assert(rpb=="")
	print("test_0:  ok")
end

--~ cmd = "local p2=({...})[1].p2; " .. "return p3, p2"
--~ cmd = "return req"
--~ rcode, rpb = rxc.request(rxs, cmd, "hello")
--~ print(111, repr(rcode), repr(rpb))

--~ rxs.smk=('a'):rep(32)
--~ cmd = "return nil, 'some error'"
--~ cmd = "return 123"
--~ cmd = "return he.stohex(req.nonce) if"
--~ r, msg = rxc.file_upload(rxs, "./zzhello", "Hello, upload!")
--~ print(222, repr(r), repr(msg))
--~ r, msg = rxc.file_download(rxs, "./zzhello")

--~ cmd=[[export ZZAA="Zaaaaa" ; exec sh -c 'echo "env: $ZZAA" ' ]]
--~ r, msg = rxc.run_basic_shell(rxs, cmd)
--~ print(222, repr(r), repr(msg))
--~ os.exit()

function test_1()  -- lua with basic request()
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

function test_2()  -- run_basic_shell
	sh = "ls /"
	rcode, rpb = rxc.run_basic_shell(rxs, sh)
	assert(rcode==0)
	assert(rpb:match("\nvar"))
	sh = "ls --zozo  2>&1 " -- invalid option, exitcode=2
	rcode, rpb = rxc.run_basic_shell(rxs, sh)
	assert(rcode==2)
	assert(rpb:match("unrecognized option"))
	print("test_2:  ok")
end

function test_3()  -- run_basic_lua 
	-- req is the first chunk argument: ({...})[1]
	-- run_basic_lua() prefixes the chunk with req definition:
	r, msg = rxc.run_basic_lua(rxs, "return req.p2", "hello")
	assert(r=="hello")
	assert(msg==nil)
	-- syntax error
	r, msg = rxc.run_basic_lua(rxs, "end if do")
	assert(r==nil)
	assert(msg:match("invalid chunk"))
	-- return error with string msg
	r, msg = rxc.run_basic_lua(rxs, "return nil, 'error'")
	assert(r==nil)
	assert(msg=="error")
	-- return error with numeric exit code
	r, msg = rxc.run_basic_lua(rxs, "return nil, 123")
	assert(r==nil)
	assert(msg=="123")
	print("test_3:  ok")
end

function test_4()  -- kill server
	r, msg = rxc.run_basic_lua(rxs, 
		"rxd.exitcode = 1", "", "stop server")
	assert(r=="")
	assert(msg==nil)
	print("test_4:  ok")
end

function test_5()  -- restart server
	r, msg = rxc.run_basic_lua(rxs, 
		"rxd.exitcode = 0", "", "restart server")
	assert(r=="")
	assert(msg==nil)
	print("test_5:  ok")
end

function test_6()  -- upload / download
	r, msg = rxc.file_upload(rxs, "./zzhello", "Hello, upload!")
	print(222, repr(r), repr(msg))
	assert(r=="true")
	assert(msg==nil)
	r, msg = rxc.file_download(rxs, "./zzhello")
--~ 	print(222, repr(r), repr(msg))
	assert(r=="Hello, upload!")
	assert(msg==nil)
	-- remove the file
	cmd = [[os.remove"./zzhello"]]
	r, msg = rxc.run_basic_lua(rxs, cmd, "", "remove")
	assert(r=="")
	assert(msg==nil)
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



