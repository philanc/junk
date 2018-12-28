-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rx 

181227  v2. 
	48-byte ecb = magic(2) time(6) cb mac
	cb = p1len pblen
	pb = p1 p2
	rcb = rcode rpblen

181228  
	removed magic
	restruct code to 
	- make protocol more indep from transport
	- separate server code from client ??




]]

------------------------------------------------------------------------
-- tmp path adjustment
package.path = "../he/?.lua;" .. package.path

------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks
local hezen = require 'hezen'
local hesock = require 'hesock'

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end


local function log(...)
--~ 	print(he.isodate():sub(10), ...)
	print(he.isodate(), ...)
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
-- client functions

local function send_request(req)
	local r, errmsg
	req.server, errmsg = hesock.connect(req.rx.rawaddr)
	if not req.server then 
		return nil, errmsg
	end
	r = wrap_req(req)
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
	if not ercb then
		return nil, "read ercb error " .. repr(errmsg)
	end
	if #ercb < ERCBLEN then
		errmsg = "read " .. repr(#ercb) .. " bytes"
		return nil, "read ercb error " .. repr(errmsg)
	end
	r, errmsg = unwrap_resp_cb(req, ercb)
	if not r then
		return nil, "unwrap_resp_cb error " .. repr(errmsg)
	end
	-- now read rpb if any
	if req.rpblen > 0 then 
		local erpblen = req.rpblen + MACLEN
		erpb, errmsg = req.server:read(erpblen)
		if (not erpb) or #erpb < erpblen then
			return nil, "cannot read erpb " .. repr(errmsg)
		end
		r, errmsg = unwrap_resp_pb(req, erpb)
		if not r then
			return nil, "unwrap_resp_pb error"
		end
	end
	return req
end --read_resp()

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

local function request(rxs, p1, p2)
	local r, errmsg
	local req = { 
		rx = rxs,
		p1 = p1, 
		p2 = p2, 
		rpb = "",
	}
	r, errmsg = request_req(req)
	if not r then 
		return nil, errmsg
	end
	return req.rcode, req.rpb
end --request()

-----------------------------------------------------------------------
-- SERVER


-----------------------------------------------------------------------
-- server - ban system and anti-replay and other utilities


local function check_not_banned(req)
	local r
	r = req.rx.whitelist[req.client_ip]
	if r then 
		-- (whitelist overrides banned list)
		return r 
	end
	r = not req.rx.banned_ip_tbl[req.client_ip]
	if not r then
		he.incr(req.rx.banned_ip_tbl, req.client_ip)
		if req.rx.log_already_banned then 
			log("already banned ip, tries", 
			    req.client_ip,
			    req.rx.banned_ip_tbl[req.client_ip])
		end
	end
	return r
end
	
local function ban_if_needed(req)
	local tries = he.incr(req.rx.ban_tries, req.client_ip)
	if tries > req.rx.ban_max_tries then
		he.incr(req.rx.banned_ip_tbl, req.client_ip)
		req.rx.log("BANNED", req.client_ip)
	end
end

local function ban_counter_reset(req)
	-- clear the try-counter (after a valid request)
	req.rx.ban_tries[req.client_ip] = nil
	-- auto whitelist
	req.rx.whitelist[req.client_ip] = true
end

local function init_ban_list(rx)
	-- ATM, start with empty lists
	rx.ban_tries = {}
	rx.banned_ip_tbl = {}
	rx.whitelist = {}
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


-- max difference between request time and server time
-- defined in server rxs.max_time_drift
--
local function time_is_valid(req)
	return math.abs(os.time() - req.reqtime) < req.rx.max_time_drift
end


local function shell(s)
	local r, exitcode = he.shell(s)
	return r, exitcode
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


local function read_request(req)
	local cb, ecb, errmsg, epb, r
	ecb, errmsg = req.client:read(ECBLEN)
	if (not ecb) or #ecb < ECBLEN then
		return reject(req, "cannot read req ecb", errmsg)
	end
	get_reqtime_nonce(req, ecb)
	if not time_is_valid(req) then 
		return reject(req, "invalid req time")
	end
	if used_nonce(req) then
		return reject(req, "already used nonce")
	end
	r, errmsg = unwrap_req_cb(req, ecb)
	if not r then 
		return reject(req, errmsg)
	end
	-- req cb is valid => can reset try-counter if set
	ban_counter_reset(req)
	--
	-- now read pb if any
	if req.pblen > 0 then 
		local epblen = req.pblen + MACLEN
		epb, errmsg = req.client:read(epblen)
		if (not epb) or #epb < epblen then
			return abort(req, "cannot read req epb", errmsg)
		end
		r, errmsg = unwrap_req_pb(req, epb)
		if not r then
			return abort(req, "unwrap_req_pb error")
		end
	else
		-- in case p1 copy is optimized out, 
		-- replace req.p1 with req.pb below
		req.p1, req.p2 = "", ""
	end
	return req
end --read_req()


local function handle_cmd(req)
	--
--~ 	he.pp(req)
	local c = req.p2
	c = (#c < 28) and c or (c:sub(1,28) .. "...")
	c = c:gsub("%s+", " ")
	req.rx.log(strf("ip=%s port=%s cmd=%s", 
		req.client_ip, tostring(req.client_port), repr(c) ))
		
	-- if p2 is empty, return server time in rcode (server "ping")
	if #req.p2 == 0 then
		req.rcode = os.time()
		req.rpb = ""
		return true
	end
	-- p2 is the lua cmd
	local chunk, r, err
	chunk, err = load(req.p2, "p2", "bt")
	if not chunk then
		req.rcode = 999
		req.rpb = "invalid chunk: " .. err
		return true
	end
	r, err = chunk(req)
	if not r then
		if err then
			req.rcode = 1
			req.rpb = tostring(err)
		else
			req.rcode = 0
			req.rpb = ""
		end
	elseif math.type(err) == "integer" then
		req.rcode = err
		req.rpb = tostring(r)
	else
		req.rcode = 0
		req.rpb = tostring(r)
	end
	return true
end

local function send_response(req)
	local ercb, erpb, r, errmsg
	r = wrap_resp(req)
	r, errmsg = req.client:write(req.ercb)
	if not r then
		return abort(req, "send resp cb error", errmsg)
	end
	if req.erpb then
		r, errmsg = req.client:write(req.erpb)
		if not r then
			return abort(req, "send resp pb error", errmsg)
		end
	end
--~ 	print("sent response")
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

--~ 	if r then
--~ 		rx.log("served client", req.client_ip, req.client_port)
--~ 	end
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
	return exitcode
end--server()

------------------------------------------------------------------------
-- default parameters

local function server_set_defaults(rxs)
	-- set some defaults values for a server
	--	
	rxs.magic = 0x01 -- magic number for regular request
	rxs.max_time_drift = 300 -- max secs between client and server time
	rxs.ban_max_tries = 3  -- number of tries before being banned
	rxs.log_rejected = true 
	rxs.log_aborted = true
	rxs.log = log
	-- 
end --server_set_defaults()

------------------------------------------------------------------------
-- rx module

local rx = {
	pack_cb = pack_cb,
	unpack_cb = unpack_cb,
	shell = shell,
	wrap_req = wrap_req,
	unwrap_req_cb = unwrap_req_cb,
	unwrap_req_pb = unwrap_req_pb,
	wrap_req = wrap_req,
	unwrap_resp_cb = unwrap_resp_cb,
	unwrap_resp_pb = unwrap_resp_pb,
	request_req = request_req,
	request = request,
	serve = serve,
	server_set_defaults = server_set_defaults,
}

return rx
