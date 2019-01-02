-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxd


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
-- common rx utilities

local rx = require "rx"



-----------------------------------------------------------------------
-- the rx server object
-- make it global (so it can be used in conf chunks)
rxd = {}


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
	ecb, errmsg = req.client:read(rx.ECBLEN)
	if (not ecb) or #ecb < rx.ECBLEN then
		return reject(req, "cannot read req ecb", errmsg)
	end
	rx.get_reqtime_nonce(req, ecb)
	if not time_is_valid(req) then 
		return reject(req, "invalid req time")
	end
	if used_nonce(req) then
		return reject(req, "already used nonce")
	end
	r, errmsg = rx.unwrap_req_cb(req, ecb)
	if not r then 
		return reject(req, errmsg)
	end
	-- req cb is valid => can reset try-counter if set
	ban_counter_reset(req)
	--
	-- now read pb if any
	if req.pblen > 0 then 
		local epblen = req.pblen + rx.MACLEN
		epb, errmsg = req.client:read(epblen)
		if (not epb) or #epb < epblen then
			return abort(req, "cannot read req epb", errmsg)
		end
		r, errmsg = rx.unwrap_req_pb(req, epb)
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
	r = rx.wrap_resp(req)
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
	rxs.bind_rawaddr = rxs.bind_rawaddr or 
		hesock.make_ipv4_sockaddr(rxs.bind_addr, rxs.port)
	local server = assert(hesock.bind(rxs.bind_rawaddr))
	rxs.log(strf("server bound to %s port %d", 
		rxs.bind_addr, rxs.port))
	print("getserverinfo(server)", hesock.getserverinfo(server, true))
	
--~ 	rxs.exitcode = 1
	while not rxs.exitcode do
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
	return rxs.exitcode
end--server()

------------------------------------------------------------------------
-- default parameters

function rxd.set_defaults(rxs)
	-- set some defaults values for a server
	--	

	-- 
end --set_defaults()


------------------------------------------------------------------------
-- server utilities 

local function shell(s)
	local r, exitcode = he.shell(s)
	return r, exitcode
end

local function load_config()
	local name, chunk, r, msg
 	-- name = arg[1] or rxd.config_filename
	-- doesn't work with lua -e "require'rxd'.test()" 
	-- arg[1] is "-e" :-(

	name = rxd.config_filename
	if not name then 
		return nil, "no config file"
	end
	chunk, msg = loadfile(name)
	if not chunk then
		return nil, msg
	end
	r, msg = pcall(chunk)
	if not r then
		return nil, "config file execution error"
	end
	return true
end
	

------------------------------------------------------------------------
-- run server

-- default functions
rxd.log = log
rxd.shell = shell -- "execute a shell command" 


-- set default server parameters
rxd.max_time_drift = 300 -- max secs between client and server time
rxd.ban_max_tries = 3  -- number of tries before being banned
rxd.log_rejected = true 
rxd.log_aborted = true
rxd.debug_mode = true
rxd.log_already_banned = true

-- load config
rxd.config_filename="./rxd.conf.lua"
local r, msg = load_config()
if not r then
	rxd.log("rxd load_config error: " .. msg)
	print("rxd load_config error", msg)
	os.exit(2)
end



-- serve() return value can be used by a wrapping script to either
-- stop or restart the server. convention is to restart server if 
-- exitcode is 0.
os.exit(serve(rxd))


