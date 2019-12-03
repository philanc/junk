-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxcore - rxc/rxd common definitions

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

		- len(4)    :: int32  - unencrypted data size
		- code(4)   :: int32  - code and arg are request or 
		- arg(8)    :: int64    response arguments interpreted 
		                        by req handler and client
	
	code and arg are interpreted by the application layers (client
	and server request handler). The convention is to use 'code' 
	as a request opcode or a response status code, and arg as an 
	optional additional argument. In many cases the request 
	or response data is really small (8 bytes or less). In these
	cases, arg can be use and eliminate the need for an additional
	encrypted data block.
	
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

local VERSION = "0.7"


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
			-- = #data(=4) + code(=4) + arg(=8) + mac(16)

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


local function get_nonce(eblock)
	-- extract nonce, reqid and time form an encrypted block
	local nonce = sunpack("c16", eblock)
	local reqid, ctr = sunpack("c15I1", nonce)
	return nonce, reqid, ctr
end
	
local function make_nonce(reqid, ctr)
	-- nonce = reqid(15) .. ctr(1)
	return spack("c15I1", reqid, ctr)
end

local function parse_nonce(nonce)
	local reqid, ctr = sunpack("c15I1", nonce)
	local time = sunpack("<I4", nonce)
	return reqid, time, ctr
end

local function new_reqid()
	local reqid = spack("<I4c11", os.time(), randombytes(11))
	return reqid
end

------------------------------------------------------------------------
-- header and data encryption/decryption

local function wrap_hdr(key, reqid, ctr, code, arg, datalen)
	local nonce = make_nonce(reqid, ctr)
	local h = spack("<I4I4i8", datalen, code, arg)
	local ehdr = encrypt(key, nonce, h)
	return ehdr, nonce
end

local function unwrap_hdr(key, reqid, ctr, ehdr)
	local nonce = make_nonce(reqid, ctr)
	local hdr, err = decrypt(key, nonce, ehdr)
	if not hdr then return nil, "unwrap_header: " .. err end
	local len, code, arg = sunpack("<I4I4i8", hdr)
	return len, code, arg
end

local function wrap_data(key, reqid, ctr, data)
	local nonce = make_nonce(reqid, ctr)
	-- edata is _not_ prefixed with the used nonce 
	local edata = encrypt(key, nonce, data)
	return edata
end

local function unwrap_data(key, reqid, ctr, edata)
	local nonce = make_nonce(reqid, ctr)
	local data, err = decrypt(key, nonce, edata)
	if not data then return nil, "unwrap_data: " .. err end
	return data
end

local function wrap_req(key, code, arg, data)
	-- return reqid, encrypted header, encrypted data (or nil if no data)
	-- the encrypted header is prefixed with the nonce.
	data = data or ""
	arg = arg or 0
	local reqid = new_reqid()
	local ehdr, nonce = wrap_hdr(key, reqid, 0, code, arg, #data) -- ctr=0
	local edata
	if #data > 0 then
		edata = wrap_data(key, reqid, 1, data) -- ctr=1
	end
	return reqid, nonce, ehdr, edata
end

local function wrap_resp(key, reqid, code, arg, data)
	data = data or ""
	local ehdr = wrap_hdr(key, reqid, 2, code, arg, #data) -- ctr=2
	-- here, nonce is NOT prepended to ehdr
	local edata
	if #data > 0 then
		edata = wrap_data(key, reqid, 3, data) -- ctr=3
	end
	return ehdr, edata
end

-- 



------------------------------------------------------------------------
-- rxcore module

local rxcore = {
	new_reqid = new_reqid,     -- () => rid
	get_nonce = get_nonce,     -- (ehdr|edata) => rid
	make_nonce = make_nonce,   -- (rid, ctr) => nonce
	parse_nonce = parse_nonce, -- (nonce) => rid, time, ctr
	wrap_hdr = wrap_hdr,       -- (k, rid, ctr, code, arg, len) => ehdr
	wrap_data = wrap_data,     -- (k, rid, ctr, data) => edata
	unwrap_hdr = unwrap_hdr,   -- (k, ehdr) => rid, ctr, len, code, arg
	unwrap_data = unwrap_data, -- (k, rid, ctr, edata) => data
	wrap_req = wrap_req,       -- (k, code, arg, data) => rid, ehdr, edata
	wrap_resp = wrap_resp,     -- (k, rid, code, arg, data) => ehdr, edata

	HDRLEN = HDRLEN,
	MACLEN = MACLEN,
	NONCELEN = NONCELEN,

	VERSION = VERSION,
}

return rxcore
