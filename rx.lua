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

local he = require 'he'
local hefs = require 'hefs'
local hezen = require 'hezen'
local hepack = require 'hepack'
local hesock = require 'hesock'

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack
local ssplit = he.split
local startswith, endswith = he.startswith, he.endswith
local pp, ppl, ppt = he.pp, he.ppl, he.ppt

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end


local function repr(x)
	return strf("%q", x) 
end

local function log(...)
	print(he.isodate():sub(10), ...)
end

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
--[[ rx server


same nonce used for the 4 encr, different counters 
	req.cb	nonce, ctr=0
	req.pb	nonce, ctr=1
	resp.cb	nonce, ctr=2
	resp.pb	nonce, ctr=3
		

]]

local CBLEN = 16
local ADLEN = 32
local ECBLEN = ADLEN + CBLEN + MACLEN

-- magic number for regular request
MAGIC = 0x0807060504030201

-- max difference between request time and server time
MAX_TIME_DRIFT = 300  

local function magic_is_valid(magic)
	return magic == MAGIC
end

local function time_is_valid(time)
	return math.abs(os.time() - time) < MAX_TIME_DRIFT
end

local function timekey(mk, time)
	-- derive a key based on time from master key
	-- (maybe memoize it?)
	local n16 = ('\x5a'):rep(16)
	local tk = encrypt(mk, n16, spack("<I8I8", time, time))
	assert(#tk == KEYLEN)
	return tk
end


local cb_fmt = "<I2I6I8" -- code, plen, paux
local ad_fmt = "<I8I8c16" -- magic, reqtime, nonce

local function pack_cb(code, pblen, paux)
	paux = paux or 0
	return spack(cb_fmt, code, pblen, paux)
end

local function unpack_cb(cb)
	return sunpack(cb_fmt, cb)
end

local function pack_ad(magic, reqtime, nonce)
	return spack(ad_fmt, magic, reqtime, nonce)
end

local function unpack_ad(ecb)
	local magic, reqtime, nonce = sunpack(ad_fmt, ecb)
	return magic, reqtime, nonce
end



------------------------------------------------------------------------
-- utilities


-- ban system

local BAN_MAX_TRIES = 3

local function check_not_banned(req)
	return not req.rx.banned_ip_tbl[req.client_ip]
end
	
local function ban_if_needed(req)
	local tries = he.incr(req.rx.ban_tries, req.client_ip)
	if tires > BAN_MAX_TRIES then
		req.rx.banned_ip_tbl[req.client_ip] = true
	end
end

local function ban_counter_reset(req)
	-- clear the try-counter (after a valid request)
	req.rx.ban_tries[req.client_ip] = nil
end

local function init_ban_list(rx)
	-- ATM, start with empty list
	rx.ban_tries = {}
end
	
local function init_used_nonce_list(rx)
	-- ATM, start with empty list
	rx.nonce_tbl = {}
end
	
local function used_nonce(req)
	-- determine if nonce has recently been used
	-- then set it to used
	local  r = req.rx.nonce_tbl[req.nonce]
	req.rx.nonce_tbl[req.nonce] = true
	return r
end

local function reject(req, msg1, msg2)
	msg2 = msg2 or ""
	-- the request is invalid
	
	ban_if_needed(req)
	if req.rx.log_rejected then
		req.rx.log("REJECTED", req.client_ip, msg1, msg2)
	end
	-- close the client connection
	return false
end

local function abort(req, msg1, msg2)
	-- the request is valid but someting went wrong
	-- close the client connection
	if req.rx.log_aborted then
		req.rx.log("ABORTED", req.client_ip, msg1, msg2)
	end
	return false
end


local function make_req_ecb(req, code, pb, paux)
	local reqtime = req.reqtime or os.time()
	local magic = req.magic or MAGIC
	local nonce = req.nonce or hezen.randombytes(NONCELEN)
	paux = paux or 0
	pb = pb or ""
	local cb = pack_cb(code, #pb, paux)
	local ad = pack_ad(magic, reqtime, nonce)
	req.tk = timekey(req.rx.smk, reqtime)
	req.ecb = encrypt(req.tk, nonce, cb, 0, ad) -- ctr=0
	assert(#req.ecb == ECBLEN)
	req.epb = encrypt(req.tk, nonce, pb, 1) -- ctr=1
	return req
end

local function unwrap_req_ecb(req, ecb)
	req.magic, req.reqtime, req.nonce = unpack_ad(ecb)
	if not magic_is_valid(req.magic) then 
		return nil, "invalid req magic"
	end
	if not time_is_valid(req.reqtime) then 
		return nil, "invalid req time"
	end
	if used_nonce(req) then
		return nil, "already used nonce"
	end
	req.tk = timekey(req.rx.smk, req.reqtime)
	cb = decrypt(req.tk, req.nonce, ecb, 0, ADLEN) -- ctr=0
	if not cb then
		return nil, "ecb decrypt error"
	end
	req.code, req.pblen, req.paux = unpack_cb(cb)
	return req
end

local function unwrap_req_epb(req, epb)
	print(111, #epb)
	local pb = decrypt(req.tk, req.nonce, epb, 1) -- ctr=1
	if not pb then
		return nil, "epb decrypt error"
	end
	req.pb = pb
	return req
end

local function read_req(req)
	local cb, ecb, errmsg, epb, r
	ecb, errmsg = req.client:read(ECBLEN)
	if (not ecb) or #ecb < ECBLEN then
		return reject(req, "cannot read req ecb", errmsg)
	end
	r, errmsg = unwrap_req_ecb(req, ecb)
	if not r then 
		return reject(req, errmsg)
	end
	-- cb valid => can reset try-counter if set
	ban_counter_reset(req)
	--
	-- now read pb if any
	if pblen > 0 then 
		local epblen = pblen + MACLEN
		epb, errmsg = req.client:read(epblen)
		if (not epb) or #epb < epblen then
			return abort(req, "cannot read req epb", errmsg)
		end
		local pb = decrypt(req.tk, nonce, epb, 1 ) -- ctr=1
		if not pb then
			return abort(req, "epb decrypt error")
		end
		req.pb = pb
	end
	return req
end


	

------------------------------------------------------------------------
-- rx server

local function serve_client(client)
	-- process a client request:
	--    get a request from the client socket
	--    call the command handler
	--    send the response to the client
	--    close the client connection
	--    return to the server main loop
	--
	local r, errmsg
	local client_ip, client_port = hesock.getclientinfo(req.client, true)
	local req = {
		rx = rx, 
		client = client,
		client_ip = client_ip, 
		client_port = client_port,
	}
	r = check_not_banned(req)
	    and read_req(req)
	    and handle_cmd(req)
	    and send_response(req)

	if r then
		rx.log("served client", req.client_ip)
	end
	hesock.close(client) 
end--serve_client()

-- the server main loop
local function serve(rx)
	-- server main loop:
	-- 	wait for a client
	--	call serve_client() to process client request
	--	rinse, repeat
	local client, msg
	init_ban_list(rx)
	init_used_nonce_list(rx)
	local server = assert(hesock.bind(rx.rawaddr))
	rx.log(strf("hehs bound to %s ", repr(rx.rawaddr)))
	print("getserverinfo(server)", hesock.getserverinfo(server, true))
	rx.must_exit = 1
	while not rx.must_exit do
		client, msg = hesock.accept(server)
		if not client then
			rx.log("rx.serve(): accept() error", msg)
		elseif rx.debug_mode then 
--~ 			rx.log("serving client", client)
			-- serve and close the connection
			serve_client(client) 
--~ 			rx.log("client closed.", client)
		else
			pcall(serve_client, client)
		end
	end--while
	if client then hesock.close(client); client = nil end
	-- TODO should be: 	close_all_clients(rx)
	local r, msg = hesock.close(server)
	rx.log("hehs closed", r, msg)
	local exitcode = rx.must_exit
	rx.must_exit = nil  --WHY??
	return exitcode
end--server()


------------------------------------------------------------------------
-- run 



rxs = {}

-- bind raw address  (localhost:3090)
rxs.rawaddr = '\2\0\x0c\x12\127\0\0\1\0\0\0\0\0\0\0\0'
-- bind_address = '::1'    -- for ip6 localhost

-- server state
rxs.must_exit = nil  -- server main loop exits if true 
		     -- handlers can set it to an exit code
		     -- convention: 0 for exit, 1 for exit+reload

-- debug_mode
-- true => request handler is executed without pcall()
--	   a handler error crashes the server
rxs.debug_mode = true

-- server log function
-- default is to print messages to stdout.
rxs.log = log  

-- server master key
rxs.smk = ('k'):rep(32)

--~ serve(rxs)

init_ban_list(rxs)
init_used_nonce_list(rxs)

req = { rx = rxs }
--~ req.reqtime = (1 << 30)|1
--~ req.nonce = ("`"):rep(16)
r = make_req_ecb(req, 3, "abcdef", 10)
px(req.ecb)
px(req.tk)

req2 = { rx = rxs }
r, msg = unwrap_req_ecb(req2, req.ecb)
print("unwrap", r, msg)

r, msg = unwrap_req_epb(req2, req.epb)
print("unwrap pb", r, msg)

pp(req2)

