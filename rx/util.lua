-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
-- simple utility functions

local spack, sunpack, strf = string.pack, string.unpack, string.format

util = {}

function util.pf(...) print(strf(...)) end

function util.px(s, msg) -- hex dump the string s
	if msg then print(msg) end
	for i = 1, #s-1 do
		io.write(strf("%02x", s:byte(i)))
		if i%4==0 then io.write(' ') end
		if i%8==0 then io.write(' ') end
		if i%16==0 then io.write('') end
		if i%32==0 then io.write('\n') end
	end
	io.write(strf("%02x\n", s:byte(#s)))
end

function util.repr(x) return string.format('%q', x) end

function util.rpad(s, w, ch) 
	-- pad s to the right to width w with char ch
	return (#s < w) and s .. ch:rep(w - #s) or s
end

function util.lstrip(s)
	-- remove whitespace at beginning of string s
	s = string.gsub(s, '^%s+', '')
	return s  -- return only 1st value returned by gsub
end

function util.rstrip(s) 
	-- remove whitespace at end of string s
	s = string.gsub(s, '%s+$', '')
	return s  -- return only 1st value returned by gsub
end

function util.strip(s) 
	-- remove whitespace at both ends of string s
	return util.lstrip(util.rstrip(s)) 
end

-- hex representation of binary strings

function util.stohex(s, ln, sep)
	-- stohex(s [, ln [, sep]])
	-- return the hex encoding of string s
	-- ln: (optional) a newline is inserted after 'ln' bytes 
	--	ie. after 2*ln hex digits. Defaults to no newlines.
	-- sep: (optional) separator between bytes in the encoded string
	--	defaults to nothing (if ln is nil, sep is ignored)
	-- example: 
	--	stohex('abcdef', 4, ":") => '61:62:63:64\n65:66'
	--	stohex('abcdef') => '616263646566'
	--
	local strf, byte = string.format, string.byte
	if #s == 0 then return "" end
	if not ln then -- no newline, no separator: do it the fast way!
		return (s:gsub('.', 
			function(c) return strf('%02x', byte(c)) end
			))
	end
	sep = sep or "" -- optional separator between each byte
	local t = {}
	for i = 1, #s - 1 do
		t[#t + 1] = strf("%02x%s", s:byte(i),
				(i % ln == 0) and '\n' or sep) 
	end
	-- last byte, without any sep appended
	t[#t + 1] = strf("%02x", s:byte(#s))
	return table.concat(t)	
end --stohex()

function util.hextos(hs, unsafe)
	-- decode an hex encoded string. return the decoded string
	-- if optional parameter unsafe is defined, assume the hex
	-- string is well formed (no checks, no whitespace removal).
	-- Default is to remove white spaces (incl newlines)
	-- and check that the hex string is well formed
	local tonumber, char = tonumber, string.char
	if not unsafe then
		hs = string.gsub(hs, "%s+", "") -- remove whitespaces
		if string.find(hs, '[^0-9A-Za-z]') or #hs % 2 ~= 0 then
			error("invalid hex string")
		end
	end
	return (hs:gsub(	'(%x%x)', 
		function(c) return char(tonumber(c, 16)) end
		))
end -- hextos

function util.errm(err, txt)
	-- errm(17, "open") => "open error: 17"
	-- errm(17)         => "error: 17"
	-- errm(0, "xyz")   => nil
	if err == 0 then return end
	local s = "error: " .. tostring(err)
	return txt and (txt .. " " .. s) or s
end
	
function util.fget(fname)
	-- return content of file 'fname' or nil, msg in case of error
	-- if fname is '-', then read from stdin
	local f, msg, s
	if fname == "-" then
		s, msg = io.read("*a")
		if not s then return nil, msg end
		return s
	end
	f, msg = io.open(fname, 'rb')
	if not f then return nil, msg end
	s, msg = f:read("*a")
	f:close()
	if not s then return nil, msg end
	return s
end

function util.fput(fname, content)
	-- write 'content' to file 'fname'
	-- if fname is '-', then write to stdout
	-- return true in case of success, or nil, msg in case of error
	local f, msg, r
	if fname == "-" then
		r, msg = io.write(content)
		if not r then return nil, msg else return true end
	end
	f, msg = io.open(fname, 'wb')
	if not f then return nil, msg end
	r, msg = f:write(content)
	f:flush(); f:close()
	if not r then return nil, msg else return true end
end

function util.isots(t, utcflag)
	-- return ISO date-time (local time) as a string that can be 
	-- used as a timestamp, an identifier or a filename 
	-- eg. 20090709_122122
	local fmt = "%Y%m%d_%H%M%S"
	if utcflag then fmt = "!" .. fmt end
	return os.date(fmt, t)
end

function util.sh(cmd)
	-- execute a shell command
	-- if the command succeeds (exit code = 0) then return the stdout
	-- if popen() succeeds but the command fails (exit code > 0)
	--   then return nil msg where msg is one line "Exit: <n>"
	--   concatenated with the cmd stdout
	-- if popen() fails, then return nil, popen_error_msg
	--
	local f, r, err, succ, status, exit
	f, err = io.popen(cmd, "r")
	if not f then return nil, util.errm(err, "popen") end
	r, errm = f:read("a")
	if not r then return nil, util.errm(err, "popen read") end
	succ, exit, status = f:close()
	status = (exit=='signal' and status+128 or status)
	if status > 0 then 
		return nil, strf("Exit: %d\n%s", status, r)
	else
		return r
	end
end

function util.keys(t)
	-- return table t string keys sorted and concatenated as a string
	local kt = {}
	for k,v in pairs(t) do
		if type(k) == "string" then table.insert(kt, k) end
	end
	table.sort(kt)
	return table.concat(kt, ", ")
end

------------------------------------------------------------------------
return util
