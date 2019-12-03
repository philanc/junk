-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxd


]]

------------------------------------------------------------------------
-- tmp path adjustment
--~ package.path = "../he/?.lua;" .. package.path

------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks
local hezen = require 'he.zen'
local sock = require 'l5.sock'

local traceback = require("debug").traceback

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end


local function log(fmt, ...)
	print(he.isodate(), strf(fmt, ...))
end


------------------------------------------------------------------------
-- common rx utilities

local rxcore = require "rxcore"



-----------------------------------------------------------------------
rxd = {  -- the rxd module
	log = log,
}
-----------------------------------------------------------------------






-----------------------------------------------------------------------
-- server - ban system and anti-replay and other utilities


local function check_not_banned(rxd, client_ip)
	local r
	r = rxd.whitelist[client_ip]
	if r then 
		-- (whitelist overrides banned list)
		return r 
	end
	r = not rxd.banned_ip_tbl[client_ip]
	if not r then
		he.incr(rxd.banned_ip_tbl, client_ip)
		if rxd.log_already_banned then 
			log("already banned ip, tries", 
			    client_ip,
			    rxd.banned_ip_tbl[client_ip])
		end
	end
	return r
end
	
local function ban_if_needed(client_ip)
	local tries = he.incr(rxd.ban_tries, client_ip)
	if tries > rxd.ban_max_tries then
		he.incr(rxd.banned_ip_tbl, client_ip)
		rxd.log("BANNED", client_ip)
	end
end

local function ban_counter_reset(client_ip)
	-- clear the try-counter (after a valid request)
	rxd.ban_tries[client_ip] = nil
	-- auto whitelist
	rxd.whitelist[client_ip] = true
end

local function init_ban_list()
	-- ATM, start with empty lists
	rxd.ban_tries = {}
	rxd.banned_ip_tbl = {}
	rxd.whitelist = {}
end
	
local function init_used_nonce_list()
	-- ATM, start with empty list
	rxd.nonce_tbl = {}
end
	
local function used_nonce(nonce)
	-- determine if nonce has recently been used
	-- then set it to used
	local  r = rxd.nonce_tbl[nonce]
	rxd.nonce_tbl[nonce] = true
	return r
end


-- max difference between request time and server time
-- defined in server rxd.max_time_drift
--
local function time_is_valid(reqtime)
	return math.abs(os.time() - reqtime) < rxd.max_time_drift
end

local function handle_cmd(ctx, cmd, data)
	-- return status:int, resp:string
	--
--~ 	he.pp(ctx)
	-- log cmd (first loglen bytes only)
	local loglen = 50
	local c = cmd
	c = (#c < loglen) and c or (c:sub(1,loglen) .. "...")
	c = c:gsub("%s+", " ")
	rxd.log(strf("%s:%s %s", 
		ctx.client_ip, tostring(ctx.client_port), repr(c) ))
	
	-- empty cmd: server "ping"
	if #cmd == 0 then 
		return 0, "" 
	end
	-- find the cmd handler
	local h, handler
	h, cmd = cmd:match("^(%S-): (.*)$")
	if not h then 
		return 2, "no handler name"
	end
	handler = ctx.handlers[h]
	if not handler then 
		return 3, "unknown handler"
	end
	-- call the handler
	-- (handler signature: handler(ctx, cmd, data) => status, resp)
	return handler(ctx, cmd, data)
end --handle_cmd

local function try_serve_client(ctx)
end

local function serve_client(server, cso)
	-- return false, exitcode to request the server loop to exit. 
	--   the exitcode value can be use to ask the server to shudown 
	--   or to restart.
	
	local csa = sock.getpeername(cso) -- get client sockaddr
	local cip, cport = sock.sockaddr_ip_port(sa)
	
	-- test if the client is valid (not banned)
	-- if not, drop the connection without any response
	if client_is_banned(server, cip) then
		sock.close(cso)
		return true
	end
	
	local r, eno, msg
	local nonce, ehdr, edata, hdr, data
	local reqid, time
	local datalen, code, arg
	local rcode, rarg, rdata
	
	-- read nonce
	nonce, eno = sock.read(cso, rxcore.NONCELEN)
	if not nonce then msg = "reading nonce"; goto cerror end
	reqid, time = rxcore.parse_nonce(nonce)
	
	if is_reqid_reused(server, reqid)
		eno = -1
		msg = "reqid reused"
		ban_if_needed(server, cip)

	if not is_time_valid(time) then
		eno = -1
		msg = "invalid time"
		ban_if_needed(server, cip)
	end
	
	-- read req header
	ehdr, eno = sock.read(cso, rxcore.HDRLEN)
	if not ehdr then msg = "reading ehdr"; goto cerror end
	
	--unwrap req header (ctr=0)
	datalen, code, arg = rxcore.unwrap_hdr(server.key, reqid, 0, ehdr)
	if not datalen then 
		msg = "header decrypt error"
		ban_if_needed(server, cip)
		eno = -1
		goto cerror
	else
		-- header is valid (the header has been properly 
		-- decrypted, so the client is assumed to be genuine.)
		-- => reset the ban try counter for the client ip
		ban_reset(server, cip)
	end
	
	-- read data if needed
	if datalen > 0 then 
		edata, eno = sock.read(cso, datalen + rxcore.MACLEN)
		if not edata then msg = "reading edata"; goto cerror end
		-- unwrap data (ctr=1)
		data, msg = unwrap_data(server.key, reqid, 1, edata)
		if not data then
			eno = -1
			-- msg is set above
			goto cerror
		end
	end
	
	-- handle the request
	local handler = find_req_handler(server, code)
	rcode, rarg, rdata = handler(reqid, code, arg, data)
	
	-- send the response
	rhdr, rdata = rxcore.wrap_resp(server.key, reqid, rcode, rarg, rdata)
	
	r, eno = sock.write(cso, rhdr)
	if not r then msg = "sending rhdr"; goto cerror end

	if rdata then 
		r, eno = sock.write(cso, rdata)
		if not r then msg = "sending rdata"; goto cerror end
	end
	
	do  -- this do block because return MUST be the last stmt of a block
		return true 
	end

	::cerror::
	sock.close(cso)
	log(strf("client %s %d: errno: %d  (%s)", cip, cport, eno, msg)
	return true

end --serve_client()

	

------------------------------------------------------------------------
-- the server main loop

function rxd.serve(server)
	-- server main loop:
	-- 	wait for a client
	--	call serve_client() to process client request
	--	rinse, repeat
	local cso, sso, r, eno, msg
	init_ban_list(server)
	init_used_nonce_list(server)
	server.bind_sockaddr = server.bind_sockaddr or 
		sock.make_ipv4_sockaddr(server.bind_addr, server.port)
	sso, msg = sock.bind(server.bind_sockaddr))
	rxd.log("server bound to %s port %d", rxd.bind_addr, rxd.port)
	
	local r, exitcode
	while not r do
		cso, eno = sock.accept(server)
		if not client then
			rxd.log("rxd.serve: accept error:", eno)
		else
			r, exitcode = serve_client(server, cso) 
		end
	end--while
	if cso then sock.close(cso); cso = nil end
	-- TODO should be: 	close_all_clients(server)
	local r, msg = sock.close(sso)
	rxd.log("server closed", r, msg)
	return exitcode
end--server()


------------------------------------------------------------------------
-- handlers

function rxd.handlers.lua(ctx, cmd, data)
	-- execute lua 'cmd'; return rcode, rpb
	local chunk, r, err, rcode, rpb
	-- define ctx as local in chunk
	-- (ctx is the first arg passed to chunk, chunk args is '...')
	cmd = "local ctx = ({...})[1]; " .. cmd
	-- add data to ctx so it can be accessed by the lua chunk
	ctx.data = data
	chunk, err = load(cmd, "cmd", "bt")
	if not chunk then
		return 2, "invalid chunk: " .. err
	end
	r, err = chunk(ctx) -- must pass ctx to chunk
	-- chunk is assumed to return rpb, or nil, errmsg
	if not r and not err then 
		return 0, ""
	elseif not r then
		return 1, tostring(err)
	else
		return 0, tostring(r)
	end
end --rxd.handlers.lua

function rxd.handlers.uld(ctx, cmd, data)
	-- upload file to server
	-- file content is data, filename is cmd
	local r, msg = he.fput(cmd, data)
	if not r then
		return 1, msg
	else
		return 0, ""
	end
end

function rxd.handlers.dld(ctx, cmd)
	-- download file to client
	-- filename is cmd
	local r, msg = he.fget(cmd)
	if not r then
		return 1, msg
	else
		return 0, r
	end
end

function rxd.handlers.sh0(ctx, cmd)
	-- raw shell, no stdin, no NX definition
	--
	local r, exitcode = he.shell(s)
	return exitcode, r
end

function rxd.handlers.sh(ctx, cmd, data)
	-- basic shell, if #data > 0, stdin is in data
	-- (default Lua popen cannot handle stdin and stdout
	--  => copy input to a tmp file, then add input redirection
	--  to the command)
	-- an environment variable NX is defined with value ctx.nonce 
	-- as an hex string.
	--
	local r, exitcode, tmpdir, ifn, msg, nx
	nx = he.stohex(ctx.nonce)
	cmd = "NX=" .. nx .. "\n" .. cmd
	if #data == 0 then
		r, exitcode = he.shell(cmd)
		return exitcode, r
	end
	local tmpdir = rxd.tmpdir or '.'
	local ifn = strf("%s/%s.in", tmpdir, nx)
	local r, msg = he.fput(ifn, data)
	if not r then
		return nil, "cannot store stdin"
	end
	cmd = strf('%s < %s', cmd, ifn)
	r, exitcode = he.shell(cmd)
	-- remove input file
	os.remove(ifn)
	return exitcode, r
end --rxd.handlers.sh



------------------------------------------------------------------------
-- run server

-- default functions
rxd.log = log

-- set default server parameters
rxd.max_time_drift = 300 -- max secs between client and server time
rxd.ban_max_tries = 3  -- number of tries before being banned
rxd.log_rejected = true 
rxd.log_aborted = true
rxd.debug = true
rxd.log_already_banned = true
rxd.tmpdir = os.getenv"/tmp" or "/tmp"

-- load config
local conf = require "rxconf"

-- copy conf values in rxd
for k,v in pairs(conf) do rxd[k] = v end

-- run the server
os.exit(rxd.serve())

-- serve() return value can be used by a wrapping script to either
-- stop or restart the server. convention is to restart server if 
-- exitcode is 0.

--~ return rxd


