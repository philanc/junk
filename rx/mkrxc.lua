#!/bin/env slua

-- mkrxc for rx18

local util = require "util"
local strf = string.format

-- append conf

local confname = arg[1]

if not confname then 
	print("Usage:  mkrxc confname    (eg.  mkrxc test)")
	os.exit(1)
end

local conf = assert(util.fget(confname .. ".conf"))

local st = { "--  DO NOT EDIT THIS FILE  --", conf }

-- append modules

local ml = {
	"util",
	"ssock",
	"rx",
}

local fmtmod = 
[[
-- #####################################################################
-- module:  %s

package.preload[%q] = function()
%s
end --module: %s

]]

local m, mf, name

for i, name in ipairs(ml) do
	m = util.fget(name .. ".lua")
	mf = strf(fmtmod, name, name, m, name)
	table.insert(st, mf)
end

-- append main

local fmtmain = [[

-- #####################################################################
-- main:   rxc

%s

]]

local main = util.fget("rxcli.lua")
main = strf(fmtmain, main)
table.insert(st, main)

local s = table.concat(st, "\n\n")

local outname = "rxc-" .. confname .. ".lua"
util.fput(outname, s)

print("rx client stored in:", outname)

-- use srlua / srglue to make an executable

local cmd = strf([[#!/bin/sh
  set -e
  srd=/ut/s/bin
  fname=rxc-%s
  $srd/srglue $srd/srlua $fname.lua $fname.bin
  chmod +x $fname.bin
	]], confname)

local r, msg = util.sh(cmd)

if r then
	print("srlua: ok")
else
	print("slrlua failed:")
	print(msg)
end




	
	
	
	