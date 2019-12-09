

server = require "rxconf"

rxc = require "rxc"
rxcore = require "rxcore"

he = require 'he'  -- make he global for request chunks
local hezen = require 'he.zen'
local hepack = require 'he.pack'

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

local function test_01()
	print("req", rxc.request(server, "hello"))
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
	local rt, msg, ctx = rxc.request(server, dt)
	if not rt then 
		print("!! rxc.request error: ", msg, ctx)
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
		require'hei'
		pp(package.loaded)
		return {ok=true}
	]]
	local rt, msg, ctx = rxc.request(server, dt)
	if not rt then 
		print("!! rxc.request error: ", msg, ctx)
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
		require'hei'
		print("nonce:", he.stohex(reqt.nonce))
		print("--------------------")
		return {ok=true}
	]]
	local rt, msg = rxc.lua(server, luacmd)
	print('msg:', msg)
	pp(rt)
end

local function test_05()
	print("--------------------test_05")
	local r, msg = rxc.sh(server, "ls -l")
	print(r, msg)
end

local function test_05a()
	print("--------------------test_05a")
	local r, msg = rxc.sh(server, 'echo "popen process pid: $$" ')
	print(r, msg)
end

local function test_06()
	print("--------------------test_06")
	local luacmd = [[
		require'hei'
		ex = 1
		pf("os.exit(%d) .............", ex)
		os.exit(ex)
 		--return {ok=true}
	]]
	local rt, msg = rxc.lua(server, luacmd)
	print(rt and rt.errmsg or msg)
--~ 	pp(rt)
end

local function test_times()
	print("--------------------test_times")
	local luacmd = [[
		local reqt = ...
		require'hei'
		local hepack = require 'he.pack'
		rt = {}
		rt.reqtime = string.unpack("<I4", reqt.nonce)
		rt.servtime = os.time()
		rt.ok = true
		print("--------------------")
		return rt
	]]
	local rt, msg = rxc.lua(server, luacmd)
	pf("client time: %d   server time: %d   client-server: %d",
		rt.reqtime, rt.servtime, rt.reqtime - rt.servtime )
end

local function test_shutdown0()
	print("--------------------shutdown requested!!")
	pp(rxc.request(server, {exitcode=rxcore.SHUTDOWN} ))
end

local function test_restart()
	print("--------------------restart requested!!")
	rxc.lua(server, "return {ok=true, exitcode=0}" )
end

local function test_shutdown()
	print("--------------------shutdown requested!!")
	rxc.lua(server, "return {ok=true, exitcode=1}" )
end

--~ test_01()
--~ test_02()
--~ test_03()
--~ test_04()
--~ test_05()
--~ test_05a()
test_06()
--~ test_times()

if arg[1] == "0" then test_restart() end
if arg[1] == "1" then test_shutdown() end



