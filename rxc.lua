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

local he = require 'he'
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

a=1

if a == 0 then
	print(rx.request(rxs, 3, 0, "abcdefghi"))
elseif a == 1 then
	req = { rx = rxs }
--~ 	req.reqtime = (1 << 30)|1
	req.nonce = ("`"):rep(16)
	req.code = 2
	print(rx.request_req(req))
	rx.disp_resp(req)
end

