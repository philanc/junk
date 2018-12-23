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


------------------------------------------------------------------------
-- common utilities

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


local CBLEN = 16
local ADLEN = 32
local ECBLEN = ADLEN + CBLEN + MACLEN
local ERCBLEN = CBLEN + MACLEN

-- magic number for regular request
MAGIC = 0x0807060504030201


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

local function disp_req(req)
	print("req.code:", req.code)
	print("req.paux:", req.paux)
	print("req.pb:", repr(req.pb))
end

local function disp_resp(req)
	print("req.rcode:", req.rcode)
	print("req.rpaux:", req.rpaux)
	print("req.rpb:", repr(req.rpb))
end


------------------------------------------------------------------------
-- client utilities 


local function make_req_ecb(req, code, pb, paux)
	local paux = paux or req.paux
	local pb = pb or req.pb
	local code = code or req.code
	local reqtime = req.reqtime or os.time()
	local magic = req.magic or MAGIC
	req.nonce = req.nonce or hezen.randombytes(NONCELEN)
	paux = paux or 0
	pb = pb or ""
	local cb = pack_cb(code, #pb, paux)
	local ad = pack_ad(magic, reqtime, req.nonce)
	req.tk = timekey(req.rx.smk, reqtime)
	req.ecb = encrypt(req.tk, req.nonce, cb, 0, ad) -- ctr=0
--~ 	assert(#req.ecb == ECBLEN)
	if #pb > 0 then
		req.epb = encrypt(req.tk, req.nonce, pb, 1) -- ctr=1
	end
	return req
end

local function send_request(req)
	local r, errmsg
	req.server, errmsg = hesock.connect(req.rx.rawaddr)
	if not req.server then 
		return nil, errmsg
	end
	r = make_req_ecb(req)
	r, errmsg = req.server:write(req.ecb)
	if not r then 
		return nil, "cannot send ecb " .. repr(errmsg)
	end
	if req.epb then 
		r, errmsg = req.server:write(req.epb)
		if not r then 
			return nil, "cannot send epb " .. repr(errmsg)
		end
	end
	return true
end --send_request

local function read_response(req)
	local cb, ercb, rcb, erpb, rpb, r, errmsg
	ercb, errmsg = req.server:read(ERCBLEN)
	if (not ercb) or #ercb < ERCBLEN then
		return nil, "cannot read ercb " .. repr(errmsg)
	end
	rcb = decrypt(req.tk, req.nonce, ercb, 2) -- ctr=2
	if not rcb then
		return nil, "ercb decrypt error"
	end
	req.rcode, req.rpblen, req.rpaux = unpack_cb(rcb)	
	
	-- now read rpb if any
	if req.rpblen > 0 then 
		local erpblen = req.rpblen + MACLEN
		erpb, errmsg = req.server:read(erpblen)
		if (not erpb) or #erpb < erpblen then
			return nil, "cannot read erpb " .. repr(errmsg)
		end
		req.rpb = decrypt(req.tk, req.nonce, erpb, 3) -- ctr=3
		if not req.rpb then
			return nil, "erpb decrypt error"
		end
	end
	return req
end --read_resp()

------------------------------------------------------------------------
-- client functions

local function request_req(req)
	-- send a pre-initialized request and read response
	-- allows to test specific params (reqtime, nonce, ...)
	local r, errmsg
	r, errmsg = send_request(req)
	if not r then
		return nil, errmsg
	end
	r, errmsg = read_response(req)
	if not r then
		return nil, errmsg
	end
	return req
end --request_req()

local function request(rxs, code, paux, pb)
	local r, errmsg
	pb = pb or ""
	paux = paux or 0
	req = { 
		rx = rxs,
		code = code,
		paux = paux,
		pb = pb,
	}
	r, errmsg = request_req(req)
	if not r then 
		return nil, errmsg
	end
	return req.rcode, req.rpaux, req.rpb
end --request()

-----------------------------------------------------------------------
-- SERVER

-----------------------------------------------------------------------
-- server - ban system and anti-replay and other utilities

local BAN_MAX_TRIES = 3

local function check_not_banned(req)
	return not req.rx.banned_ip_tbl[req.client_ip]
end
	
local function ban_if_needed(req)
	local tries = he.incr(req.rx.ban_tries, req.client_ip)
	if tries > BAN_MAX_TRIES then
		req.rx.banned_ip_tbl[req.client_ip] = true
		req.rx.log("BANNED", req.client_ip)
	end
end

local function ban_counter_reset(req)
	-- clear the try-counter (after a valid request)
	req.rx.ban_tries[req.client_ip] = nil
end

local function init_ban_list(rx)
	-- ATM, start with empty lists
	rx.ban_tries = {}
	rx.banned_ip_tbl = {}
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

-- max difference between request time and server time
MAX_TIME_DRIFT = 300  

local function magic_is_valid(magic)
	return magic == MAGIC
end

local function time_is_valid(time)
	return math.abs(os.time() - time) < MAX_TIME_DRIFT
end

--

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
	local pb = decrypt(req.tk, req.nonce, epb, 1) -- ctr=1
	if not pb then
		return nil, "epb decrypt error"
	end
	req.pb = pb
	return req
end

local function read_request(req)
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
	if req.pblen > 0 then 
		local epblen = req.pblen + MACLEN
		epb, errmsg = req.client:read(epblen)
		if (not epb) or #epb < epblen then
			return abort(req, "cannot read req epb", errmsg)
		end
		r, errmsg = unwrap_req_epb(req, epb)
		if not r then
			return abort(req, "epb decrypt error")
		end
	end
	return req
end --read_req()


local function handle_cmd(req)
	-- tbd
	disp_req(req)
	-- set response
	req.rcode = req.code + 1000
	req.rpaux = req.paux + 1000
	req.rpb = "req.pb: " .. tostring(req.pb)
	
--~ 	req.rx.must_exit = 1
	return true
end

local function send_response(req)
	-- tbd
	local ercb, erpb, r, errmsg
	local rpb = req.rpb or ""
	req.ercb = encrypt(req.tk, req.nonce, 
		pack_cb(req.rcode, #rpb, req.rpaux), 2) -- ctr=2 
	if #rpb > 0 then 
		req.erpb = encrypt(req.tk, req.nonce, rpb, 3) -- ctr=3
	end
	r, errmsg = req.client:write(req.ercb)
	if not r then
		return abort(req, "send resp ercb", errmsg)
	end
	if req.erpb then
		r, errmsg = req.client:write(req.erpb)
		if not r then
			return abort(req, "send resp erpb", errmsg)
		end
	end
	print("sent response")
	return true
end --send_response()	

------------------------------------------------------------------------
-- main server functions

local function serve_client(rx, client)
	-- process a client request:
	--    get a request from the client socket
	--    call the command handler
	--    send the response to the client
	--    close the client connection
	--    return to the server main loop
	--
	local r, errmsg
	local client_ip, client_port = hesock.getclientinfo(client, true)
	local req = {
		rx = rx, 
		client = client,
		client_ip = client_ip, 
		client_port = client_port,
	}
	r = check_not_banned(req)
	    and read_request(req)
	    and handle_cmd(req)
	    and send_response(req)

	if r then
		rx.log("served client", req.client_ip, req.client_port)
	end
	hesock.close(client) 
end--serve_client()

-- the server main loop
local function serve(rxs)
	-- server main loop:
	-- 	wait for a client
	--	call serve_client() to process client request
	--	rinse, repeat
	local client, msg
	init_ban_list(rxs)
	init_used_nonce_list(rxs)
	local server = assert(hesock.bind(rxs.rawaddr))
	rxs.log(strf("hehs bound to %s ", repr(rxs.rawaddr)))
	print("getserverinfo(server)", hesock.getserverinfo(server, true))
--~ 	rx.must_exit = 1
	while not rxs.must_exit do
		client, msg = hesock.accept(server)
		if not client then
			rxs.log("rx serve(): accept error", msg)
		elseif rxs.debug_mode then 
--~ 			rxs.log("serving client", client)
			-- serve and close the connection
			serve_client(rxs, client) 
--~ 			rxs.log("client closed.", client)
		else
			pcall(serve_client, rxs, client)
		end
	end--while
	if client then hesock.close(client); client = nil end
	-- TODO should be: 	close_all_clients(rxs)
	local r, msg = hesock.close(server)
	rxs.log("hehs closed", r, msg)
	local exitcode = rxs.must_exit
	rxs.must_exit = nil  --WHY??
	return exitcode
end--server()


------------------------------------------------------------------------
-- rx module

local rx = {
	pack_cb = pack_cb,
	unpack_cb = unpack_cb,
	make_req_ecb = make_req_ecb,
	unwrap_req_ecb = unwrap_req_ecb,
	unwrap_req_epb = unwrap_req_epb,
	disp_req = disp_req,
	disp_resp = disp_resp,
	read_response = read_response,
	send_request = send_request,
	request_req = request_req,
	request = request,
	serve = serve,
}

return rx