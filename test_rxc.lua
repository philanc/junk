

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

local function test_shutdown()
	print("shutdown!!", rxc.request(server, {exitcode=rxcore.SHUTDOWN} ))
end

test_01()
test_shutdown()


