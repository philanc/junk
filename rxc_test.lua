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
rxd = {}

-- default localhost test config
-- bind raw address  (localhost:4096)
-- rxd.rawaddr = '\2\0\1\0\127\0\0\1\0\0\0\0\0\0\0\0'
-- bind_address = '::1'    -- for ip6 localhost

rxd.addr = "127.0.0.1"
rxd.port = 4096
rxd.rawaddr = hesock.make_ipv4_sockaddr(rxd.addr, rxd.port)
rxd.smk = ('k'):rep(32) -- server master key

-- server info
rxd = { 
	log = print,
	config_filename = "rxd.conf.lua",
}
assert(rxc.load_rxd_config())

------------------------------------------------------------------------

	
-- prepare req

req = { rxs = rxd }
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
	rcode, rpb = rxc.request(rxd, "", "")
--~ 	print(111, repr(rcode), repr(rpb))
	assert(rcode, "??? maybe server not started ???")
	assert(math.abs(rcode - os.time()) < 300 )
	assert(rpb=="")
	print("test_0:  ok")
end

function test_1()  -- lua with basic request()
	cmd = "lua: x = 123 "  -- return nil
	rcode, rpb = rxc.request(rxd, cmd, "")
	assert(rcode==0)
	assert(rpb=="")
	cmd = "lua: return'hello' "  -- return string
	rcode, rpb = rxc.request(rxd, cmd, "")
	assert(rcode==0)
	assert(rpb=="hello")
	cmd = "lua: 3 + if "  -- syntax error
	rcode, rpb = rxc.request(rxd, cmd, "")
--~ 	print(111, rcode, repr(rpb))
	assert(rcode==2)
	cmd = "lua: return nil, 'some error' "  -- exec error
	rcode, rpb = rxc.request(rxd, cmd, "")
	assert(rcode==1)
	assert(rpb=="some error")
	cmd = [[lua: -- access req object
	a = { ... }; req = a[1]
	return req.rxs.smk
	]]
	rcode, rpb = rxc.request(rxd, cmd, "")
	assert(rcode==0)
	assert(rpb==rxd.smk)
	print("test_1:  ok")
end

function test_2()  -- run_basic_shell
	sh = "ls /"
	r, exitcode = rxc.shell(rxd, sh)
	assert(exitcode==0)
	assert(r:match("\nvar"))
	sh = "ls --zozo  2>&1 " -- invalid option, exitcode=2
	r, exitcode = rxc.shell(rxd, sh)
	assert(exitcode==2)
	assert(r:match("unrecognized option"))
	print("test_2:  ok")
	-- test NX defined
	sh = "echo $NX"
	r, exitcode = rxc.shell(rxd, sh)
--~ 	print(111, repr(rcode), repr(rpb), #rpb)
	assert(exitcode==0)
	assert(r:match("^%x+\n"))	
	assert(#he.strip(r) == 32)	
end

function test_3()  -- lua 
	-- req is the first chunk argument: ({...})[1]
	-- lua() prefixes the chunk with req definition:
	r, msg = rxc.lua(rxd, "return req.p2", "hello")
	assert(r=="hello")
	assert(msg==nil)
	-- syntax error
	r, msg = rxc.lua(rxd, "end if do")
	assert(r==nil)
	assert(msg:match("invalid chunk"))
	-- return error with string msg
	r, msg = rxc.lua(rxd, "return nil, 'error'")
	assert(r==nil)
	assert(msg=="error")
	-- return error with numeric exit code
	r, msg = rxc.lua(rxd, "return nil, 123")
	assert(r==nil)
	assert(msg=="123")
	print("test_3:  ok")
end

function test_4()  -- kill server
	r, msg = rxc.lua(rxd, 
		"rxd.exitcode = 1", "", "stop server")
	assert(r=="")
	assert(msg==nil)
	print("test_4:  ok")
end

function test_5()  -- restart server
	r, msg = rxc.lua(rxd, 
		"rxd.exitcode = 0", "", "restart server")
	assert(r=="")
	assert(msg==nil)
	print("test_5:  ok")
end

function test_6()  -- upload / download
	r, msg = rxc.file_upload(rxd, "./zzhello", "Hello, upload!")
	assert(r==true)
	assert(msg==nil)
	r, msg = rxc.file_download(rxd, "./zzhello")
--~ 	print(222, repr(r), repr(msg))
	assert(r=="Hello, upload!")
	assert(msg==nil)
	-- remove the file
	cmd = [[os.remove"./zzhello"]]
	r, msg = rxc.lua(rxd, cmd, "")
	assert(r=="")
	assert(msg==nil)
	cmd = [[ --test removed
		s, msg = he.fget("./zzhello")
		return s, msg
	]]
	r, msg = rxc.lua(rxd, cmd)
--~ 	print(111, repr(r), repr(msg))
	assert(not r)
	assert(msg:match"No such file")
	print("test_6:  ok")
end

function test_7() -- shell with stdin
	cmd = "wc -l"
	sin = "abc\ndef\n"
	r, exitcode = rxc.shell(rxd, cmd, sin)
	assert(exitcode==0)
	assert(r:match("^2\n"))
	print("test_7:  ok")
end

function test_8()
	for i = 1, 100 do 
		rcode, rpb = rxc.request(rxd, "", "")
		assert(rcode, "??? maybe server not started ???")
		assert(math.abs(rcode - os.time()) < 300 )
		assert(rpb=="")
	end
end

function test_10()
	local m = he.fget("mb10")
	r, msg = rxc.file_upload(rxd, "./mb10", m)
--~ 	print(222, repr(r), repr(msg))
	assert(r=="true")
	print("test_10:  ok")
end



--~ test_8()
--~ test_10()
--~ os.exit()


test_0() -- ping
test_1() -- basic lua
test_2() -- basic shell
test_3() -- lua env

test_5() -- restart server
hesock.msleep(2000) -- wait for server to restart

test_6() -- upload / download
test_7() -- shell with stdin
test_4() -- kill server

os.exit(11)


