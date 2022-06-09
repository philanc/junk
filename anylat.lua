#!/bin/env lua


--[[

220609	  anylat:  test if file includes any latin chars
		   that are not part of a valid utf8 sequence

Usage:	toutf8 filein 

	filein can be "-" (or empty) for stdin

Notes:  
	ignore well-formed utf8 sequences.

]]

he = require "he"

sf = string.format

-- works in 2 steps:
-- 	1. replace valid utf8 sequences with @@<n>## where n is the codepoint
--	2. check for latin1 chars


pat1 = "[\xC2-\xF4][\x80-\xBF]*" -- valid, non ascii, utf8 sequences
function repl1(u)
	local r, code = pcall(utf8.codepoint, u)
	if r then u = sf("@@<%d>##", code)  end
	return u
end


pat2 = "[\xA0-\xFF]" -- valid latin1 chars (ignore control chars \x80-\x9F)

function check(s)
	s = string.gsub(s,  pat1, repl1) -- escape utf8 sequences
	if s:find(pat2) then 
		print(arg[1], "Latin1 char found.")
		os.exit()
	else
		print(arg[1], "No Latin1 char found.")
		os.exit(1)
	end
end

local t0 = he.fget(arg[1])

check(t0)
