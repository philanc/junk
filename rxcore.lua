-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxcore - rxc/rxd common definitions


]]


local VERSION = "0.5"


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

local HDRLEN = 8
local ADLEN = 24
local EC_HDRLEN = ADLEN + HDRLEN + MACLEN  --encrypted cmd header length
local ER_HDRLEN = HDRLEN + MACLEN  --encrypted resp header length

local function timekey(mk, time)
	-- derive a key based on time from master key mk
	-- (maybe memoize it?)
	local n16 = ('\x5a'):rep(16)
	local tk = encrypt(mk, n16, spack("<I8I8", time, time))
	assert(#tk == KEYLEN)
	return tk
end


local hdr_fmt = "<I4I4" -- (cmdlen, datalen) or (status, resplen)
local ad_fmt = "<I8c16" -- (reqtime, nonce)

local function pack_hdr(c1, c2)
	return spack(hdr_fmt, c1, c2)
end

local function unpack_hdr(hdr)
	return sunpack(hdr_fmt, hdr)
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

local function encrypt_req(ctx, cmd, data)
	data = data or ""
	cmd = cmd or ""
	local reqtime = ctx.reqtime or os.time()
	ctx.tk = timekey(ctx.smk, reqtime)
	ctx.nonce = ctx.nonce or hezen.randombytes(NONCELEN)
	local hdr = pack_hdr(#cmd, #data)
	local ad = pack_ad(reqtime, ctx.nonce)
	local ehdr, ecmd, edata
	ehdr = encrypt(ctx.tk, ctx.nonce, hdr, 0, ad) -- ctr=0
	if #cmd > 0 then
		ecmd = encrypt(ctx.tk, ctx.nonce, cmd, 1) -- ctr=1
	end
	if #data > 0 then
		edata = encrypt(ctx.tk, ctx.nonce, data, 2) -- ctr=2
	end
	return ehdr, ecmd, edata
end

local function get_reqtime_nonce(ehdr)
	-- not included in decrypt_reqhdr() to allow the server
	-- to check reqtime and nonce validity before decrypting
	return unpack_ad(ehdr)
end

local function decrypt_reqhdr(ctx, ehdr)
	-- get_reqtime_nonce() must be called before decrypt_reqhdr()
	-- to initialize ctx.reqtime and ctx.nonce
	--
	-- compute the reqtime-based key used for the request/response 
	ctx.tk = timekey(ctx.smk, ctx.reqtime)
	local hdr = assert(decrypt(ctx.tk, ctx.nonce, ehdr, 0, ADLEN), 
		"reqlen decrypt error")  -- ctr=0
	-- here the request issuer is assumed to be valid
	ctx.reqhdr_is_valid = true
	local cmdlen, datalen = unpack_hdr(hdr)
	return cmdlen, datalen
end

local function decrypt_cmd(ctx, ecmd)
	return assert(decrypt(ctx.tk, ctx.nonce, ecmd, 1), 
		"cmd decrypt error")  -- ctr=1
end

local function decrypt_data(ctx, edata)
	return assert(decrypt(ctx.tk, ctx.nonce, edata, 2), 
		"cmd decrypt error")  -- ctr=2
end

local function encrypt_resp(ctx, status, resp)
	local hdr = pack_hdr(status, #resp)
	local ehdr, eresp
	ehdr = encrypt(ctx.tk, ctx.nonce, hdr, 3) -- ctr=3
	if #resp> 0 then
		eresp = encrypt(ctx.tk, ctx.nonce, resp, 4) -- ctr=4
	end
	return ehdr, eresp
end
	
local function decrypt_resphdr(ctx, ehdr)
	local hdr = assert(decrypt(ctx.tk, ctx.nonce, ehdr, 3), 
		"resphdr decrypt error")  -- ctr=3
	local status, resplen = unpack_hdr(hdr)
	return status, resplen
end

local function decrypt_resp(ctx, eresp)	
	local resp = assert(decrypt(ctx.tk, ctx.nonce, eresp, 4), 
		"resp decrypt error")  -- ctr=4
	return resp
end



------------------------------------------------------------------------
-- configuration

local function load_rxd_config(rxd)
	-- load a config file for the server 'rxd'
	-- if no rxd is provided, a new object is created.
 	-- config filename = 
	--	$RXDCONF 
	--	or rxd.config_filename
	--	or "rxd.conf.lua"
	-- if no config file is found, or in case of an error, 
	-- return nil, errmsg
	-- else return rxd
	rxd = rxd or {}
	local name, chunk, env, r, msg

	name = os.getenv"RXDCONF" 
		or rxd.config_filename
		or "rxd.conf.lua"
	-- create an environment for the chunk and place rxd in it
	env = he.clone(_G)
	env.rxd = rxd
	chunk, msg = loadfile(name, "bt", env)
	if not chunk then
		return nil, msg
	end
	r, msg = pcall(chunk)
	if not r then
		return nil, "config file execution error: " .. msg
	end
	return rxd
end --load_rxd_config()


------------------------------------------------------------------------
-- rxcore module

local rxcore = {
	get_reqtime_nonce = get_reqtime_nonce,
	encrypt_req = encrypt_req,
	decrypt_reqhdr = decrypt_reqhdr,
	decrypt_cmd = decrypt_cmd,
	decrypt_data = decrypt_data,
	encrypt_resp = encrypt_resp,
	decrypt_resphdr = decrypt_resphdr,
	decrypt_resp = decrypt_resp,

	load_rxd_config = load_rxd_config,
	
	MACLEN = MACLEN,
	EC_HDRLEN = EC_HDRLEN,  --encrypted cmd header length
	ER_HDRLEN = ER_HDRLEN,  --encrypted resp header length
	
	VERSION = VERSION,
}

return rxcore
