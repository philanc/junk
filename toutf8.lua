--[[

220608    toutf8: convert a mix of latin1 and utf8 to utf8

Usage:	toutf8 filein fileout  

	filein, fileout can be "-" (or empty) for stdin, stdout
		(if fileout is not empty, filein must be provided)

Notes:  
	keep well-formed utf8 sequences as-is.  
	convert the remaining latin1 (non-ascii) bytes to utf8 sequences.
	works "most of the time" :-)  (cannot guarantee that a sequence of 
	latin1 chars isn't also a valid utf8 sequence...)

]]

he = require "he"

sf = string.format

-- works in 3 steps:
-- 	1. replace valid utf8 sequences with @@<n>## where n is the codepoint
--	2. replace latin1 chars with the corresponding utf8 sequence
--	3. replace back the @@<n>## with the original utf8 sequence


pat1 = "[\xC2-\xF4][\x80-\xBF]*" -- valid, non ascii, utf8 sequences
function repl1(u)
	local r, code = pcall(utf8.codepoint, u)
	if r then u = sf("@@<%d>##", code)  end
	return u
end


pat2 = "[\xA0-\xFF]" -- valid latin1 chars (ignore control chars \x80-\x9F)
function repl2(x)
	local code = x:byte()
	x = utf8.char(code)
	return x
end

pat3 = "@@<([%d]*)>##" -- escaped utf8 sequences
function repl3(x)
	local code =tonumber(x)
	x = utf8.char(code)
	return x
end

function convert(s)
	s = string.gsub(s,  pat1, repl1) -- escape utf8 sequences
	s = string.gsub(s,  pat2, repl2) -- replace latin chars
	s = string.gsub(s,  pat3, repl3) -- restore escaped utf8 sequences
	return s
end

local t0
if not arg[1] or arg[1] == "-" then
	t0 = io.read("a")
else
	t0 = he.fget(arg[1])
end

local t1 = convert(t0)
if not arg[2] or arg[2] == "-" then
	io.write(t1)
else
	he.fput(arg[2], t1)
end
