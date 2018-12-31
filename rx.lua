-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rx 


]]

------------------------------------------------------------------------
-- tmp path adjustment
package.path = "../he/?.lua;" .. package.path

------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks
local hezen = require 'hezen'

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

local KEYLEN = 32
local NONCELEN = 16
local MACLEN = 16


local function encrypt(key, nonce, m, ctr, ad)
	-- encrypt m with key, nonce
	-- return the encrypted message c prefixed with ad
	-- => #c = #ad + #m + MACLEN
	return hezen.morus_encrypt(key, nonce, m, ctr, ad)
end

local function decrypt(key, nonce, c, ctr, adlen)
	-- return decrypted message, nonce or nil errmsg if MAC error
	return hezen.morus_decrypt(key, nonce, c, ctr, adlen)
end

------------------------------------------------------------------------
-- protocol elements

local CBLEN = 8
local ADLEN = 24
local ECBLEN = ADLEN + CBLEN + MACLEN
local ERCBLEN = CBLEN + MACLEN


local function timekey(mk, time)
	-- derive a key based on time from master key mk
	-- (maybe memoize it?)
	local n16 = ('\x5a'):rep(16)
	local tk = encrypt(mk, n16, spack("<I8I8", time, time))
	assert(#tk == KEYLEN)
	return tk
end


local cb_fmt = "<I4I4" -- c1, c2
local ad_fmt = "<I8c16" -- reqtime, nonce

local function pack_cb(c1, c2)
	return spack(cb_fmt, c1, c2)
end

local function unpack_cb(cb)
	return sunpack(cb_fmt, cb)
end

local function pack_ad(reqtime, nonce)
	return spack(ad_fmt, reqtime, nonce)
end

local function unpack_ad(ecb)
	local reqtime, nonce = sunpack(ad_fmt, ecb)
	return reqtime, nonce
end

------------------------------------------------------------------------
-- request / response utilities 

local function wrap_req(req)
	-- after exec, encrypted control block is req.ecb
	-- if needed, encrypted param block is req.epb
	local p1 = req.p1 or ""
	local p2 = req.p2 or ""
	local pb = p1 .. p2
	req.reqtime = req.reqtime or os.time()
	req.nonce = req.nonce or hezen.randombytes(NONCELEN)
	local cb = pack_cb(#p1, #pb)
	local ad = pack_ad(req.reqtime, req.nonce)
	req.tk = timekey(req.rx.smk, req.reqtime)
	req.ecb = encrypt(req.tk, req.nonce, cb, 0, ad) -- ctr=0
	assert(#req.ecb == ECBLEN)
	if #pb > 0 then
		req.epb = encrypt(req.tk, req.nonce, pb, 1) -- ctr=1
	end
	return req
end

local function get_reqtime_nonce(req, ecb)
	-- allows to perform time and nonce validity checks before decrypting
	-- ?? is it worthwhile? could just decrypt and check after...
	-- anyway, don't check here!
	req.reqtime, req.nonce = unpack_ad(ecb)
	return req
end

local function unwrap_req_cb(req, ecb)
	req.tk = timekey(req.rx.smk, req.reqtime)
	local cb = decrypt(req.tk, req.nonce, ecb, 0, ADLEN) -- ctr=0
	if not cb then
		return nil, "ecb decrypt error"
	end
	req.p1len, req.pblen = unpack_cb(cb)
	assert(req.p1len <= req.pblen)
	return req
end

local function unwrap_req_pb(req, epb)
	local pb = decrypt(req.tk, req.nonce, epb, 1) -- ctr=1
	if not pb then
		return nil, "epb decrypt error"
	end
	-- next, split pb into p1, p2
	-- (maybe could avoid a p1 copy, in case it is eg a file upload
	--  do req.pb = pb and let app extract p1 from pb)
	if req.p1len > 0 then
		req.p2 = pb:sub(req.p1len +1)
		req.p1 = pb:sub(1, req.p1len)
	else
		req.p2 = pb
		req.p1 = ""
	end
	return req
end

local function wrap_resp(req)
	local ercb, erpb, r, errmsg
	local rpb = req.rpb or ""
	req.ercb = encrypt(req.tk, req.nonce, 
			pack_cb(req.rcode, #rpb), 2) -- ctr=2 
	if #rpb > 0 then 
		req.erpb = encrypt(req.tk, req.nonce, rpb, 3) -- ctr=3
	end
	return req
end


local function unwrap_resp_cb(req, ercb)
	local rcb = decrypt(req.tk, req.nonce, ercb, 2) -- ctr=2
	if not rcb then
		return nil, "ercb decrypt error"
	end
	req.rcode, req.rpblen = unpack_cb(rcb)	
	return req
end

local function unwrap_resp_pb(req, erpb)
	req.rpb = decrypt(req.tk, req.nonce, erpb, 3) -- ctr=3
	if not req.rpb then
		return nil, "erpb decrypt error"
	end
	return req
end


------------------------------------------------------------------------
-- rx module

local rx = {
	pack_cb = pack_cb,
	unpack_cb = unpack_cb,
	get_reqtime_nonce = get_reqtime_nonce,
	wrap_req = wrap_req,
	unwrap_req_cb = unwrap_req_cb,
	unwrap_req_pb = unwrap_req_pb,
	wrap_resp = wrap_resp,
	unwrap_resp_cb = unwrap_resp_cb,
	unwrap_resp_pb = unwrap_resp_pb,
	
	MACLEN = MACLEN,
	ECBLEN = ECBLEN,
	ERCBLEN = ERCBLEN,
}

return rx
