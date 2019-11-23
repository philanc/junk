-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxcore - rxc/rxd common definitions

v0.6
	- removed time-based key diversification
	- same header for req and resp (48 bytes)

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
local MACLEN = 16


local function encrypt(key, nonce, m, ctr)
	-- encrypt m with key, nonce
	-- ctr is added to nonce
	-- 	(builtin for hezen, to be impl for plc XXXXX)
	-- return the encrypted message c prefixed with nonce
	-- => #c = #nonce + #m + MACLEN
	return hezen.morus_encrypt(key, nonce, m, ctr)
end

local function decrypt(key, nonce, c, ctr)
	-- return decrypted message, nonce or nil errmsg if MAC error
	return hezen.morus_decrypt(key, nonce, c, ctr, adlen)
end

local function randombytes(n)
	return hezen.randombytes(n)
end

------------------------------------------------------------------------
--[[ protocol elements
	hdr	header (fixed size - 48 bytes)
		contains:
		- reqid(16) ::  time(4) .. rnd(12) -- used as nonce
		- code(4): int32 -- request code or response status
		- len(4): int32  -- data part size
		- arg(8): int64  -- arbitrary int (interpreted by req handler)
		encrypted header ends with a MAC(16)
			
	data	data part (variable size given in header field 'len')

naming convention:
	'q' query/request
	'r' response
	'e' encrypted
]]

local HDRLEN = 48 -- encrypted header length


local function get_reqid(ehdr)
	-- extract reqid and time form an encrypted header
	local reqid = ehdr:sub(1, HDRLEN)
	local time = sunpack("<I4", reqid)
	return reqid, time
end

local function new_reqid()
	local reqid = spack("<I4c12", os.time(), randombytes(12))
	return reqid
end

------------------------------------------------------------------------
-- client-side functions

local function wrap_req(key, code, arg, qdata)
	local reqid = new_reqid()
	local q = spack("<I4I4I8", code, #qdata, arg)
	local eqhdr = reqid .. encrypt(key, reqid, q, 0) --ctr=0
	local eqdata = encrypt(key, reqid, qdata, 1) --ctr=1
	return reqid, eqhdr, eqdata
end

local function unwrap_rhdr(key, erhdr)
	-- 
	local reqid, time = get_reqid(erhdr)
	local rhdr = decrypt(key, reqid, erhdr:sub(NONCELEN+1), 2) -- ctr=2
	if not rhdr then return nil, "rhdr decrypt error" end
	local code, len, arg = sunpack("<I4I4I8", rhdr)
	return reqid, code, len, arg
end

local function unwrap_rdata(key, reqid, erdata)
	local rdata = decrypt(key, reqid, erdata, 3) -- ctr=3
	if not rdata then return nil, "rdata decrypt error" end
	return rdata
end

------------------------------------------------------------------------
-- server-side functions

local function unwrap_qhdr(key, eqhdr)
	-- 
	local reqid, time = get_reqid(eqhdr)
	local qhdr = decrypt(key, reqid, eqhdr:sub(NONCELEN+1), 0) -- ctr=0
	if not qhdr then return nil, "qhdr decrypt error" end
	local code, len, arg = sunpack("<I4I4I8", qhdr)
	return reqid, code, len, arg
end

local function unwrap_qdata(key, reqid, eqdata)
	local qdata = decrypt(key, reqid, eqdata, 1) -- ctr=1
	if not qdata then return nil, "qdata decrypt error" end
	return qdata
end

local function wrap_resp(key, reqid, code, arg, rdata)
	local r = spack("<I4I4I8", code, #rdata, arg)
	local eqhdr = reqid .. encrypt(key, reqid, q, 0) --ctr=0
	local eqdata = encrypt(key, reqid, qdata, 1) --ctr=1
	return reqid, eqhdr, eqdata
end




------------------------------------------------------------------------
-- rxcore module

local rxcore = {
	new_reqid = new_reqid,
	get_reqid = get_reqid,
	wrap_req = wrap_req,
	unwrap_rhdr = unwrap_rhdr,
	unwrap_rdata = unwrap_rdata,
	unwrap_qhdr = unwrap_qhdr,
	unwrap_qdata = unwrap_qdata,
	wrap_resp = wrap_resp,

	HDRLEN = HDRLEN,
	MACLEN = MACLEN,
	NONCELEN = NONCELEN,

	VERSION = VERSION,
}

return rxcore
