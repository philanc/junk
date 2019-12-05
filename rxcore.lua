-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxcore - rxc/rxd common definitions

v0.8
	- same as v0.7 except code, arg are replaced with a rnd(12) string
	- the same rnd is used for req and resp.
	- the ban system is removed.
	
v0.7
	- same header for req and resp (32 bytes)
	- the first header block is prefixed by a nonce.

v0.6
	- removed time-based key diversification
	- same header for req and resp (48 bytes)
	- headers and data blocks are prefixed by a nonce.


protocol elements

	rx follows a client/server model: the client sends a request 
	to the server; for each request, the server sends back one response.
	
	request and response have the same structure: a fixed-size 
	header (hdr) followed by an optional variable-length 
	data block (data). The length of the data block is included 
	in the header. If the length ('len') is zero, there is 
	no data block.
	
	header and data are encrypted separately but with the same key.
	It uses authenticated symmetric encryption. This version is 
	based on Morus but the algorithm can be swapped with 
	any other authenticated encryption algo.

	hdr	header (fixed size - encrypted: 32 bytes)

		- rnd(12)   :: string - used to fuzz the header
		- len(4)    :: int32  - unencrypted data size
	
	
	encrypted header and data blocks end with a MAC(16). 
	A nonce(16) is prefixed to the request encrypted header 

	nonce structure:
		- nonce(16) :: reqid(15) .. ctr(1)
		- reqid(15) :: time(4) .. rnd(11) - must be unique
		- ctr(1)    :: small int(0..3) used to make distinct nonces
			       for all encrypted elements
	
	The main part of the nonce is the request id ('reqid'). It is the 
	same reqid that is used for the request and the response headers 
	and data block. The nonce is completed by a one-byte counter that
	ensures that all the blocks use a different nonce.
	
	The ctr value must be the following:
		request header   0	  
		request data     1
		response header  2
		response data    3
		
naming convention:
	'q' query/request
	'r' response
	'hdr'  request or response header block
	'e' encrypted (eg. ehdr, or edata)

]]

local VERSION = "0.8"


------------------------------------------------------------------------
--~ -- tmp path adjustment
--~ package.path = "../he/?.lua;" .. package.path

------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end


------------------------------------------------------------------------
-- encryption

local hezen = require 'he.zen'


local KEYLEN = 32
local NONCELEN = 16
local MACLEN = 16
local HDRLEN = 32   	-- encrypted header length (nonce not included)
			-- = #rnd(=12) + #data(=4) + #mac(=16)

-- here, should add crypto selection code (use plc if luazen not avail)

local function encrypt(key, nonce, m)
	-- encrypt m with key, nonce
	-- return the encrypted message c 
	-- => #c = #m + MACLEN
	return hezen.morus_encrypt(key, nonce, m)
end

local function decrypt(key, nonce, c)
	-- return decrypted message or nil errmsg if MAC error
	return hezen.morus_decrypt(key, nonce, c)
end

local function randombytes(n)
	return hezen.randombytes(n)
end

------------------------------------------------------------------------


local function make_noncelist(time, rnd)
	-- create a list of four distinct nonces used to encrypt/decrypt 
	-- the header and data blocks for the request and the response
	local nl = {}
	time = time or os.time()
	rnd = rnd or randombytes(11)
	for i = 1, 4 do
		table.insert(nl, spack("<I4c11i1", time, rnd, i))
	end
	return nl
end

local function parse_nonce(n)
	-- parse a nonce, extract the time, the random string 
	-- and the counter 
	local time, rnd, ctr = sunpack("<I4c11i1", n)
	return time, rnd, ctr
end


------------------------------------------------------------------------
-- header and data encryption/decryption

local function wrap_hdr(key, nonce, datalen)
	-- a random string is included to make known plaintext attacks harder
	local rnd = randombytes(12)
	local hdr = spack("c12<i4", rnd, datalen)
	local ehdr = encrypt(key, nonce, hdr)
	return ehdr
end

local function unwrap_hdr(key, nonce, ehdr)
	-- decrypt a header, return the data length
	local hdr, err = decrypt(key, nonce, ehdr)
	if not hdr then return nil, "unwrap_header: " .. err end
	local rnd, len = sunpack("c12<i4", hdr)
	return len
end

local function wrap_data(key, nonce, data)
	local edata = encrypt(key, nonce, data)
	return edata
end

local function unwrap_data(key, nonce, edata)
	local data, err = decrypt(key, nonce, edata)
	if not data then return nil, "unwrap_data: " .. err end
	return data
end

local function wrap_req(key, data)
	-- return the encrypted header, the encrypted data, the list
	-- of nonces for the request and the response.
	data = data or ""
	local nl = make_noncelist()
	local ehdr = wrap_hdr(key, nl[1], #data)
	local edata = wrap_data(key, nl[2], data)
	return ehdr, edata, nl
end

local function wrap_resp(key, nl, data)
	data = data or ""
	local ehdr = wrap_hdr(key, nl[3], #data)
	-- here, nonce is NOT prepended to ehdr
	local edata = wrap_data(key, nl[4], data)
	return ehdr, edata
end


------------------------------------------------------------------------
-- rxcore module

local rxcore = {
	make_noncelist = make_noncelist,  -- ([time]) => noncelist
	parse_nonce = parse_nonce, -- (nonce) => time, rnd, ctr
	new_reqid = new_reqid,     -- () => rid
	get_nonce = get_nonce,     -- (ehdr|edata) => rid
	make_nonce = make_nonce,   -- (rid, ctr) => nonce
	parse_nonce = parse_nonce, -- (nonce) => rid, time, ctr
	wrap_hdr = wrap_hdr,       -- (k, nonce, len) => ehdr
	wrap_data = wrap_data,     -- (k, nonce, data) => edata
	unwrap_hdr = unwrap_hdr,   -- (k, nonce, ehdr) => len
	unwrap_data = unwrap_data, -- (k, nonce, edata) => data
	wrap_req = wrap_req,       -- (k, data) => ehdr, edata, noncelist
	wrap_resp = wrap_resp,     -- (k, noncelist, data) => ehdr, edata

	HDRLEN = HDRLEN,
	MACLEN = MACLEN,
	NONCELEN = NONCELEN,

	VERSION = VERSION,
}

return rxcore
