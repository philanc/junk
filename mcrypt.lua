#!/bin/env slua

-- mcrypt - file encryption (morus / he.moe)



local mcrypt_VERSION = "mcrypt 0.1"

------------------------------------------------------------------------
-- local definitions

local strf = string.format

local function isin(elem, lst)
	-- test if elem is in a list
	for i,v in ipairs(lst) do if elem == v then return true end end
	return false
end
	
local function fget(fname)
	-- return content of file 'fname'
	local f, msg = io.open(fname, 'rb')
	if not f then return nil, msg end
	local s = f:read("a") ;  f:close()
	return s
end

local function fput(fname, content)
	-- write 'content' to file 'fname'
	local f = assert(io.open(fname, 'wb'))
	assert(f:write(content) ); 
	assert(f:flush()) ; f:close()
	return true
end

local function fileext(path)
	-- return path extension (or empty string if none)
	-- (this assume that path is a unix path - separator is '/')
	-- note: when a filename starts with '.' it is not considered 
	--    as an extension
	local base = path:match("^.+/(.*)$") or path
	return base:match("^.+%.(.*)$") or ""
end

local function perr(...) io.stderr:write(...); io.stderr:write("\n") end


------------------------------------------------------------------------
-- encryption support

local moe = require "he.moe"



------------------------------------------------------------------------
-- luazen-v0.11 support

-- pcrpyt_norx => use norx encryption

--~ local encrypt = lz.norx_encrypt --  (k, n, m, ninc, ad) => c
--~ local decrypt = lz.norx_decrypt --  (k, n, c, ninc, adlen) => p | nil,err

--~ local keylen = 32
--~ local noncelen = 32
--~ local maclen = 32

local encrypt = moe.encrypt --  (k, n, m, ninc, ad) => c
local decrypt = moe.decrypt --  (k, n, c, ninc, adlen) => m | nil,err

local keylen = moe.keylen
local noncelen = moe.noncelen
local maclen = moe.maclen


------------------------------------------------------------------------

local bsize = 1024 * 1024  -- use 1 MB blocks

local function get_key32(kfn, defaultext)
	local r, msg, key, keypath
	-- try to find kfn as-is
	key = fget(kfn)
	if key then goto checkkey end
	-- try with default ext
	kfn = kfn .. defaultext
	key = fget(kfn)
	if key then goto checkkey end
	-- try to find key in ~/.config/mcrypt/
	if not kfn:find("/") then
		keypath = os.getenv"HOME" .. "/.config/mcrypt/" .. kfn
		key = fget(keypath)
	end
	if not key then return nil, "key not found" end
	
	::checkkey::
	if #key < 32 then return nil, "invalid key" end
	if #key > 32 then key = key:sub(1, 32) end
	return key
end--get_key32()

function encrypt_file(k, fni, fno, pkflag)
	local fhi, fho --file handles
	local r, msg = nil, nil
	if fni == '-' then 
		fhi = io.stdin
	else
		fhi, msg = io.open(fni)
		if not fhi then 
			msg = msg .. " (input)"
			goto close
		end
	end
	if fno == '-' then 
		fho = io.stdout
	else
		fho, msg = io.open(fno, 'w')
		if not fho then 
			msg = msg .. " (output)"
			goto close
		end
	end
	r, msg = moe.fhencrypt(k, fhi, fho)
	
	::close::
	if fhi and fhi ~= io.stdin then assert(fhi:close()) end
	if fho and fho ~= io.stdout then assert(fho:close()) end
	return r, msg
end --encrypt_file()

function decrypt_file(k, fni, fno, pkflag)
	local fhi, fho --file handles
	local r, msg
	if fni == '-' then 
		fhi = io.stdin
	else
		fhi, msg = io.open(fni)
		if not fhi then return nil, msg .. " (input)" end
	end
	if fno == '-' then 
		return nil, "cannot decrypt to stdout."
	else
		fho, msg = io.open(fno, 'w')
		if not fho then 
			assert(fhi:close())
			return nil, msg .. " (output)" 
		end
	end
	r, msg = moe.fhdecrypt(k, fhi, fho)

	::close::
	if fhi and fhi ~= io.stdin then assert(fhi:close()) end
	if fho and fho ~= io.stdout then assert(fho:close()) end
	if not r then os.remove(fno); msg = "decrypt error" end
	return r, msg
end --decrypt_file()

function genkey(kfn)
	local k = moe.stok()
	return fput(kfn .. ".k", k)
end

function genkeypw(kfn)
	-- hack - suppress echo (unix only)
	os.execute("stty -echo")
	print("Enter password")
	local pw1 = io.read()
	print("Enter password again")
	local pw2 = io.read()
	os.execute("stty echo")
	if pw1 ~= pw2 then return nil, "entries do not match"  end
	local k = moe.stok(pw1)
	return fput(kfn .. ".k", k)	
end

usage_str = strf([[
Usage:  
	mcrypt e   key filein fileout  - encrypt file
	mcrypt d   key filein fileout  - decrypt file

	mcrypt k   kname  - generate a key (kname.k)
	mcrypt kpw kname  - generate a key (kname.k) from a password
Notes:
	key is either a keyname or a keyfile path.
	keys are also looked for in ~/.config/mcrypt/.
	"-" can be used to denote stdin or stdout.
	decryption cannot be sent to stdout.
	
	version: %s   (crypto: %s, %s)
		
]], mcrypt_VERSION, moe.use())

function main()
	local r, msg
	local op, kfn, fni, fno, k
	local opkext = {
		e   = ".k",
		d   = ".k",
	}
	local defaultext
	--
	op, kfn, fni, fno = arg[1], arg[2], arg[3], arg[4]
	if not (op and kfn) then goto usage end
	if isin(op, {'e', 'd'}) then
		if not (kfn and fni and fno) then goto usage end
		defaultext = opkext[op]
		k, msg = get_key32(kfn, defaultext)
		if not k then perr(msg); return nil end
	end
	--
	if     op == "e"   then r, msg = encrypt_file(k, fni, fno)
	elseif op == "d"   then r, msg = decrypt_file(k, fni, fno)
	elseif op == "k"   then r, msg = genkey(kfn)
	elseif op == "kpw" then r, msg = genkeypw(kfn)
	else goto usage
	end--if
	if r then
		perr(strf("mcrypt %s done.", op))
		os.exit(0)
	else
		perr(msg)
		if msg == "decrypt error" then os.exit(2) else os.exit(1) end
	end
	
	::usage::
	perr(usage_str)
	return
end


main()	


