#!/bin/env slua

local util = require "util"
local lm = require 'luamonocypher'

local name = arg[1]
if not name then
	print[[
	
Usage:   genkp name
]]
	os.exit(1)
end

local strf = string.format

local msk =  lm.randombytes(32)
local mpk =  lm.public_key(msk)

local fname = name .. ".kp"

fmt = [[
-- %s
msk="%s"
mpk="%s"
--
]]

local s = strf(fmt,
	fname,
	util.stohex(msk),
	util.stohex(mpk)
	)

assert(util.fput(fname, s))

