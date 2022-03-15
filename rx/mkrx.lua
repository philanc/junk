
local he = require "he"
local strf = string.format

local outname = "rx.lua"

local ml = {
	"util",
	"ssock",
	"rxc",
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
-- main:  rxcli.lua

%s
]]

local main = he.fget("rxcli.lua")
main = strf(fmtmain, main)

table.insert(st, main)

local s = table.concat(st, "\n\n")
he.fput(outname, s)

	
	
	
	
	
	