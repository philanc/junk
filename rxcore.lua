-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxcore - rxc/rxd common definitions

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

	hdr	header (fixed size - encrypted: 64 bytes)
		contains:
		- nonce(16) :: reqid(15) .. ctr(1)
		- reqid(15) ::  time(4) .. rnd(11) -- must be unique
		- len(4) :: int32  -- unencrypted data size
		- arg(28) -- request or response argument
			arbitrary string, interpreted by req handler
			or client for the response
			
	encrypted header and data blocks starts with a nonce and 
	ends with a MAC(16)
	
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
	'e' encrypted
]]

]]


local VERSION = "0.6"



------------------------------------------------------------------------
-- tmp path adjustment
package.path = "../he/?.lua;" .. package.path

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
-- common utilities



------------------------------------------------------------------------
-- encryption

local hezen = require 'hezen'


local KEYLEN = 32
local NONCELEN = 16
local ARGLEN = 28
local MACLEN = 16
local HDRLEN = 64	-- = NONCELEN + #len(=4) + ARGLEN + MACLEN

-- here, should add crypto selection code (use plc if luazen not avail)

local function encrypt(key, nonce, m)
	-- encrypt m with key, nonce
	-- return the encrypted message c prefixed with nonce
	-- => #c = #nonce + #m + MACLEN
	return hezen.morus_encrypt(key, nonce, m)
end

local function decrypt(key, nonce, c)
	-- return decrypted message, nonce or nil errmsg if MAC error
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
	
function make_nonce(reqid, ctr)
	-- nonce = reqid(15) .. ctr(1)
	return spack("c15I1", reqid, ctr)
end

local function new_reqid()
	local reqid = spack("<I4c11", os.time(), randombytes(11))
	return reqid
end

------------------------------------------------------------------------
-- header and data encryption/decryption

local function wrap_hdr(key, reqid, ctr, arg, datalen)
	local nonce = make_nonce(reqid, ctr)
	assert(arg and # arg <= ARGLEN)
	local h = spack("<I4c28", datalen, arg)
	local ehdr = nonce .. encrypt(key, nonce, h)
	return ehdr
end

local function unwrap_hdr(key, ehdr)
	local nonce, reqid = parse_nonce(ehdr)
	local hdr, err = decrypt(key, nonce, ehdr:sub(NONCELEN+1))
	if not hdr then return nil, "unwrap_header: " .. err end
	local len, arg = sunpack("<I4c28", hdr)
	return reqid, len, arg
end

local function wrap_data(key, reqid, ctr, data)
	local nonce = make_nonce(reqid, ctr)
	local edata = nonce .. encrypt(key, nonce, data)
	return edata
end

local function unwrap_data(key, edata, exp_reqid)
	-- exp_reqid (optional(: the expected reqid. If provided and 
	-- if it doesn't match with the reqid at the beginning of edata,
	-- the function does not decrypt and return nil, err
	local nonce, reqid = parse_nonce(edata)
	if exp_reqid and exp_reqid ~= reqid then
		return nil, "unwrap_data: unexpected reqid"
	end
	local data, err = decrypt(key, nonce, data:sub(NONCELEN+1))
	if not data then return nil, "unwrap_data: " .. err end
	return data
end



------------------------------------------------------------------------
-- rxcore module

local rxcore = {
	new_reqid = new_reqid,     -- () => reqid
	get_nonce = get_nonce,     -- (ehdr|edata) => reqid
	make_nonce = make_nonce    -- (reqid, ctr) => nonce
	wrap_hdr = wrap_hdr,       -- (key, reqid, ctr, arg, len) => ehdr
	wrap_data = wrap_data,     -- (key, reqid, ctr, data) => edata
	unwrap_hdr = unwrap_hdr,   -- (key, ehdr) => reqid, len, arg
	unwrap_data = unwrap_data, -- (key, edata, [exp_reqid] ) => data

	HDRLEN = HDRLEN,
	MACLEN = MACLEN,
	NONCELEN = NONCELEN,

	VERSION = VERSION,
}

return rxcore
