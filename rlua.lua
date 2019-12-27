
-- usage:  
--	rlua = require'rlua'
--	rlua("return 1 + 2"
--	or
--	rlua("return 1 + 2", "big addition"
--

local server = require "rxconf"
local rx = require "rx"

he = require 'he'
local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local pf = printf
local ppp = print

local luacmdfmt = [[
-- rlua cmd
require "he.i"
local rqt = ...
local function luacmdfn(rqt)
%s
end
local rt = {}
rt.r = luacmdfn(rqt)
return rt
]]

local function rlua(cmd, desc)
	-- cmd: lua code ending with "return lua_value"
	if not desc then
		desc = cmd:sub(1,20) 
		if #desc < #cmd then desc = desc .. "..." end
	end
	luacmd = strf(luacmdfmt, cmd)
--~ ppp(luacmd)	
	local rt, msg = rx.lua(server, luacmd, desc)
	if not rt then 
		return nil, strf("rx msg: %s", msg)
	elseif rt.errmsg then
		return nil, strf("rt.errmsg: %s", rt.errmsg)
	else
		return rt.r
	end
end

-- return the single rlua function
return rlua

