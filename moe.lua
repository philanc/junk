-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== moe - morus-based encryption 

(here, moe is not related to anime :-)

]]

------------------------------------------------------------------------

local spack, sunpack = string.pack, string.unpack
local byte, char = string.byte, string.char
local insert, concat = table.insert, table.concat

------------------------------------------------------------------------
local moe = {} -- the moe module table

moe.VERSION = "0.1"

local noncelen = 16
local maclen = 16
local keylen = 32

moe.noncelen = noncelen
moe.maclen = maclen
moe.keylen = keylen


local encrypt -- encrypt(k, n, plain) 
local decrypt -- decrypt(k, n, encr)
local hash    -- hash(s, diglen)
local newnonce  -- return noncelen random bytes as a string
local b64encode, b64decode

-- use luazen if it is available and built with morus, else use plc.morus

local r

local r, lz = pcall(require, "luazen")

if r and lz.morus_encrypt then 
	moe.cryptolib = "luazen"
	moe.noncegen = "randombytes"
	encrypt = lz.morus_encrypt
	decrypt = lz.morus_decrypt
	hash = lz.morus_xof
	b64encode = lz.b64encode
	b64decode = lz.b64decode
	newnonce = function() return lz.randombytes(noncelen) end
else 
	local mo, b64
	mo = require("plc.morus")
	b64 = require("plc.base64")
	moe.cryptolib = "plc"
	encrypt = mo.encrypt
	decrypt = mo.decrypt
	hash = mo.xof
	b64encode = b64.encode
	b64decode = b64.decode	
	local devrandom = io.open("/dev/urandom", "r")
	if devrandom then
		newnonce = function() return devrandom:read(noncelen) end
		moe.noncegen = "/dev/urandom"
	else
		newnonce = function() 
			return hash(os.time()..os.clock(), noncelen)
			end
		moe.noncegen = "time-based"
	end
end

-- string encryption

function moe.encrypt(k, p, armor, n)
	-- encrypt string p with key k
	-- nonce n is optional, it can be provided to obtain 
	-- a deterministic result (eg. for tests) but it is usually
	-- not provided. A random nonce is then generated.
	-- the nonce is prepended to the encrypted result
	-- if armor is true, the encrypted result is base64-encoded. 
	n = n or newnonce()
	local c = n .. encrypt(k, n, p)
	if armor then c = b64encode(c) end
	return c
end

function moe.decrypt(k, c, armor)
	-- decrypt string c. if armor, assume c is base64-encoded.
	local msg
	if armor then
		c, msg = b64decode(c)
		if not c then return nil, msg end
	end
	local n = c:sub(1, noncelen)
	c = c:sub(noncelen+1)
	local p
	p, msg = decrypt(k, n, c)
	if not p then return nil, msg end
	return p
end

------------------------------------------------------------------------
-- utility functions

function moe.stok(s)
	-- take a key string and generate a key ("string-to-key")
	-- (can be used for example to generate keys from a keyfile;
	-- this is _not_ a password key derivation function)
	local minlen = 1024
	-- ensure s is at least minlen bytes
	local slen = #s
	if slen < minlen then s = s:rep(math.ceil(minlen/slen)) end
	-- uniformize bits
	s = hash(s, keylen)
	return s
end

function moe.getnonce(c)
	return c:sub(1, noncelen)
end

------------------------------------------------------------------------
-- file encryption

-- file encryption is performed one block at a time.

local csize = 1048576 -- encrypted block size = 1 MByte
local psize = csize - noncelen - maclen -- plain block size

function moe.fhencrypt(k, fhin, fhout, finlen)
	-- encrypt from and to a file handle
	-- fhin is a file handle to an open file (mode=r).
	-- fhout is a file handle to an open file (mode=w).
	-- input and output files are _not_ closed by this function.
	-- finlen is the input length (the function attempts to read
	-- up to finlen bytes). It is optional. Default is to read up to 
	-- the end of file.
	-- return the total number of bytes written to fhout, or 
	-- nil, errmsg in case of error.
	local p, c, r, msg, cnt
	local rcnt = 0 -- total read byte counter
	local wcnt = 0 -- total write byte counter
	local min = math.min
	if io.type(fhin) ~= "file" then 
		return nil, "invalid input file handle"
	end
	if io.type(fhout) ~= "file" then 
		return nil, "invalid output file handle"
	end
	finlen = finlen or math.maxinteger
	while true do
		cnt = min(psize, finlen - rcnt)
		p, msg = fhin:read(cnt)
		if not p then --eof
			return wcnt
		end
		rcnt = rcnt + #p
		c = moe.encrypt(k, p)
		r, msg = fhout:write(c)
		if not r then return nil, "output error: " .. msg end
		wcnt = wcnt + #c
	end
end --fhencrypt()

function moe.fhdecrypt(k, fhin, fhout, finlen)
	-- decrypt from and to a file handle
	-- fhin is a file handle to an open file (mode=r).
	-- fhout is a file handle to an open file (mode=w).
	-- input and output files are _not_ closed by this function.
	-- finlen is the input length (the function attempts to read
	-- up to finlen bytes). It is optional. Default is to read up to 
	-- the end of file.
	-- return the total number of bytes written to fhout, or 
	-- nil, errmsg in case of error.
	local p, c, r, msg, cnt
	local rcnt = 0 -- total read byte counter
	local wcnt = 0 -- total write byte counter
	local min = math.min
	if io.type(fhin) ~= "file" then 
		return nil, "invalid input file handle"
	end
	if io.type(fhout) ~= "file" then 
		return nil, "invalid output file handle"
	end
	finlen = finlen or math.maxinteger
	while true do
		cnt = min(csize, finlen - rcnt)
		c, msg = fhin:read(cnt)
		if not c then --eof
			return wcnt
		end
		rcnt = rcnt + #c
		p, msg = moe.decrypt(k, c)
		if not p then return nil, "decrypt error: " .. msg end
		r, msg = fhout:write(p)
		if not r then return nil, "output error: " .. msg end
		wcnt = wcnt + #p
	end
end --fhdecrypt()
------------------------------------------------------------------------
return moe
