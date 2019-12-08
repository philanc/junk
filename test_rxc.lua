

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
		respt == {ok=true, errmsg="no error!!"}
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

local function test_shutdown()
	print("shutdown!!", rxc.request(server, {exitcode=rxcore.SHUTDOWN} ))
end

--~ test_01()
test_02()

--~ test_shutdown()


