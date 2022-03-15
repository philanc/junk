#!/bin/env slua

local util = require "util"
local lm = require 'luamonocypher'

local name = arg[1]
local addr = arg[2]
local port = arg[3]
if not (name and addr and port) then
	print[[
	
Usage:   genconf name addr port

   eg.   genconf local 127.0.0.1 4096
]]
	os.exit(1)
end

local strf = string.format

local msk =  lm.randombytes(32)
local mpk =  lm.public_key(msk)

local fname = name .. ".conf"

fmt = [[
return {
name="%s",
addr="%s",
port=%s, -- (a number, not a string)
msk="%s",
mpk="%s",
}
]]

local s = strf(fmt,
	name,
	addr,
	port,
	util.stohex(msk),
	util.stohex(mpk)
	)

assert(util.fput(fname, s))

