-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxs


]]


------------------------------------------------------------------------
-- tmp path adjustment
package.path = "../he/?.lua;" .. package.path

------------------------------------------------------------------------
-- imports and local definitions

local he = require 'he'
local hefs = require 'hefs'
local hezen = require 'hezen'
local hepack = require 'hepack'

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
-- run server

local rx = require 'rx'


rxs = {}

-- bind raw address  (localhost:3090)
rxs.rawaddr = '\2\0\x0c\x12\127\0\0\1\0\0\0\0\0\0\0\0'
-- bind_address = '::1'    -- for ip6 localhost

-- server state
rxs.must_exit = nil  -- server main loop exits if true 
		     -- handlers can set it to an exit code
		     -- convention: 0 for exit, 1 for exit+reload


rx.server_set_defaults(rxs)

-- debug_mode
-- true => request handler is executed without pcall()
--	   a handler error crashes the server
rxs.debug_mode = true

rxs.log_already_banned = true


-- server master key4
rxs.smk = ('k'):rep(32)

rx.serve(rxs)


