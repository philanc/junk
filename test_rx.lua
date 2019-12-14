

server = require "rxconf"

rx = require "rx"

he = require 'he'  -- make he global for request chunks
local hezen = require 'he.zen'
local hepack = require 'he.pack'

local traceback = require("debug").traceback

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack
local hpack, hunpack = hepack.pack, hepack.unpack

local pf = printf

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end

local function test_01()
	print("req", rx.request(server, "hello"))
end

local function test_02()
	-- test lua cmd
	local dt = {}
	dt.lua = [[ 
		local reqt = ... 
		print(reqt.lua)
		respt = {ok=true, errmsg="no error!!"}
		return respt
	]]
	local rt, msg, ctx = rx.request(server, dt)
	if not rt then 
		print("!! rx.request error: ", msg, ctx)
	else
		rt = hunpack(rt)
--~ 		he.pp(rt)
		if not rt.ok then
			print("lua cmd error:", rt.errmsg)
		end
	end
end

local function test_03()
	-- test lua cmd
	local dt = {}
	dt.lua = [[ 
		local reqt = ... 
		require'he.i'
		pp(package.loaded)
		return {ok=true}
	]]
	local rt, msg, ctx = rx.request(server, dt)
	if not rt then 
		print("!! rx.request error: ", msg, ctx)
	else
		rt = hunpack(rt)
--~ 		he.pp(rt)
		if not rt.ok then
			print("lua cmd error:", rt.errmsg)
		end
	end
end

local function test_04()
	print("--------------------test_04")
	local luacmd = [[
		local reqt = ...
		require'he.i'
		print("nonce:", he.stohex(reqt.nonce))
		print("--------------------")
		return {ok=true}
	]]
	local rt, msg = rx.lua(server, luacmd)
	print('msg:', msg)
	pp(rt)
end

local function test_05()
	print("--------------------test_05")
	local r, msg = rx.sh(server, "ls -l")
	print(r, msg)
end

local function test_05a()
	print("--------------------test_05a")
	local r, msg = rx.sh(server, 'echo "popen process pid: $$" ', "get popen proc pid")
	print(r, msg)
end

local function test_06()
	print("--------------------test_06")
	local luacmd = [[
		require'he.i'
		ex = 1
		pf("os.exit(%d) .............", ex)
		os.exit(ex)
 		--return {ok=true}
	]]
	local rt, msg = rx.lua(server, luacmd)
	print(rt and rt.errmsg or msg)
--~ 	pp(rt)
end


local function test_07()
	print("--------------------test_07 get log tail")
	local r, msg = rx.sh(server, 'tail rxd.log ', "tail rxd.log")
	print(r, msg)
end


local function test_times()
	print("--------------------test_times")
	local luacmd = [[
		local reqt = ...
		require'he.i'
		local hepack = require 'he.pack'
		rt = {}
		rt.reqtime = string.unpack("<I4", reqt.nonce)
		rt.servtime = os.time()
		rt.ok = true
		return rt
	]]
	local rt, msg = rx.lua(server, luacmd, "compare client and server times")
--~ 	he.pp(rt)
	pf("client time: %d   server time: %d   client-server: %d",
		rt.reqtime, rt.servtime, rt.reqtime - rt.servtime )
end

local function test_shutdown0()
	print("--------------------shutdown requested!!")
	pp(rx.request(server, {exitcode=rxcore.SHUTDOWN} ))
end

local function test_restart()
	print("--------------------restart requested!!")
	rx.lua(server, "return {ok=true, exitcode=0}", "restart requested" )
end

local function test_shutdown()
	print("--------------------shutdown requested!!")
	rx.lua(server, "return {ok=true, exitcode=1}", "shutdown requested" )
end

--~ test_01()
--~ test_02()
--~ test_03()
--~ test_04()
--~ test_05()
--~ test_05a()
--~ test_06()
test_07()
test_times()

if arg[1] == "0" then test_restart() end
if arg[1] == "1" then test_shutdown() end



