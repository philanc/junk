
-- moe - morus-based encryption (here, moe is not related to anime :-)

------------------------------------------------------------------------

local spack, sunpack = string.pack, string.unpack
local byte, char = string.byte, string.char
local insert, concat = table.insert, table.concat

------------------------------------------------------------------------
local moe = {} -- the moe module table

local bsize = 1048576 -- blocksize = 1 MByte

local noncelen = 16
local keylen = 32

local encrypt -- encrypt(k, n, plain) 
local decrypt -- decrypt(k, n, encr)
local hash    -- hash(s, diglen)
local b64encode, b64decode

-- use luazen if it is available and built with morus, else use plc.morus

local r

local r, lz = pcall(require, "luazen")

if r and lz.morus_encrypt then 
	encrypt = lz.morus_encrypt
	decrypt = lz.morus_decrypt
	hash = lz.morus_xof
	b64encode = lz.b64encode
	b64decode = lz.b64decode
else 
	local mo, b64
	mo = require("plc.morus")
	b64 = require("plc.base64")
	encrypt = mo.encrypt
	decrypt = mo.decrypt
	hash = mo.xof
	b64encode = b64.encode
	b64decode = b64.decode	
end

function moe.newnonce(n, i)
	-- if n and i are empty, generate a new nonce.
	-- else add i to nonce n (a noncelen-byte string)
	if not n then
		-- generate a new nonce
		-- (nonce doesn't have to be random. just not reused.)
		if lz then
			n = lz.randombytes(noncelen)
		else
			n = hash(os.time()..os.clock(), noncelen)
		end
		return n
	end
	local n1 = sunpack("<i8", n)
	n1 = n1 + i  -- no overflow here. Lua integer addition rolls over.
	return spack("<i8", n1) .. n:sub(9)
end

function moe.stok(s)
	-- take a key string and generate a key
	-- (used for example to generate keys from a keyfile)
	local minlen = 1024
	-- ensure s is at least minlen bytes
	local slen = #s
	if slen < minlen then s = s:rep(math.ceil(minlen/slen)) end
	-- uniformize bits
	s = hash(s, keylen)
	return s
end

function moe.encrypt(k, n, p, armor)
	-- encrypt string p. 
	-- the nonce is prepended to the encrypted result
	-- if armor is true, base64-encode the encrypted result
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

local k = ('k'):rep(32)
local n = moe.newnonce()
print("#n, n:", #n, b64encode(n))
local p, p2, c, msg
p = "hello"
c = moe.encrypt(k, n, p, true)
print("#c, c:", #c, c)
print(moe.decrypt(k, c, true))

	
	