
local he = require "he"
local strf = string.format

local pname = arg[1]
if not pname then
	print[[
	
Usage:   mkrxs name   (eg.  'mkrxs local')
]]
	os.exit(1)
end

local f = assert(loadfile(pname .. ".conf"))
local conf = assert(f())

local outname = strf("rxs-%s.lua", conf.name)

local ml = {
	"util",
	"ssock",
	"rxs",
}

local fmtmod = 
[[
-- #####################################################################
-- module:  %s

package.preload[%q] = function()
%s
end --module: %s

]]

local st = {}
local m, mf, name

-- append modules

for i, name in ipairs(ml) do
	m = he.fget(name .. ".lua")
	mf = strf(fmtmod, name, name, m, name)
	table.insert(st, mf)
end

-- append main

local fmtmain = 
[[
-- #####################################################################
-- main:  %s

local rxs = require"rxs"
local util = require "util"
local lm = require 'luamonocypher'
local mpk = "%s"
mpk = assert(util.hextos(mpk))
local server = { mpk = mpk,  port = %s,  }
assert(rxs.serverinit(server))
rxs.runserver(server)

]]

local main = strf(fmtmain, outname, conf.mpk, conf.port)

table.insert(st, main)

local s = table.concat(st, "\n\n")
he.fput(outname, s)

	
	
	
	
	
	