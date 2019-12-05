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
	handlers = {},  -- the request handler table
	server = {},	-- the server object
}


-----------------------------------------------------------------------






-----------------------------------------------------------------------
-- server - ban system and anti-replay and other utilities


function rxd.client_is_banned(server, client_ip)
	local r
	if server.whitelist[client_ip] then 
		-- (whitelist overrides banned list)
		return false
	end
	r = server.banned_ip_tbl[client_ip]
	if not r then 
		return false
	end
	server.banned_ip_tbl[client_ip] = r + 1
	-- here we ignore the rollover risk. 
	-- assume it is safe with int64.
	if server.log_already_banned then 
		log(strf("already banned ip %s, tries: %d", 
		    client_ip, r))
	end
	return true
end
	
function rxd.ban_counter_incr(server, client_ip)
	local tries = he.incr(server.ban_tries, client_ip)
	if tries > server.ban_max_tries then
		he.incr(server.banned_ip_tbl, client_ip)
		rxd.log("BANNED", client_ip)
	end
end

function rxd.ban_counter_reset(server, client_ip)
	-- clear the try-counter (after a valid request)
	server.ban_tries[client_ip] = nil
	-- auto whitelist
	server.whitelist[client_ip] = true
end

function rxd.init_ban_list(server)
	-- ATM, start with empty lists
	server.ban_tries = {}
	server.banned_ip_tbl = {}
	server.whitelist = {}
end
	
function rxd.init_used_reqid_list(server)
	-- ATM, start with empty list
	server.reqid_tbl = {}
end
	
function rxd.is_reqid_used(server, reqid)
	-- determine if reqid has recently been used
	-- then set it to used
	local  r = server.reqid_tbl[reqid]
	server.reqid_tbl[reqid] = true
	return r
end


-- max valid difference between request time and server time
-- defined in server server.max_time_drift
--
function rxd.is_time_valid(server, reqtime)
	return math.abs(os.time() - reqtime) < server.max_time_drift
end

local function handle_cmd(server, cmd, data)
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

function rxd.handle_req(reqid, code, arg, data)
	-- return rcode, rarg, rdata
	local rcode, rarg, rdata
	local handler = rxd.handlers[code]
	if handler then 
		rcode, rarg, rdata = handler(reqid, code, arg, data)
		rarg = rarg or 0
		rcode = rcode or -2
		return rcode, rarg, rdata
	else
		return -1, 0, nil
	end
end

local function serve_client(server, cso)
	-- return false, exitcode to request the server loop to exit. 
	--   the exitcode value can be use to ask the server to shudown 
	--   or to restart.
	
	local csa = sock.getpeername(cso) -- get client sockaddr
	local cip, cport = sock.sockaddr_ip_port(csa)
	
	-- test if the client is valid (not banned)
	-- if not, drop the connection without any response
	if rxd.client_is_banned(server, cip) then
		sock.close(cso)
		return true
	end
	
	local r, eno, msg
	local nonce, ehdr, edata, hdr, data
	local reqid, time
	local datalen, code, arg
	local handler, rcode, rarg, rdata
	
	-- read nonce
	nonce, eno = sock.read(cso, rxcore.NONCELEN)
	if not nonce then msg = "reading nonce"; goto cerror end
	reqid, time = rxcore.parse_nonce(nonce)
	
	if rxd.is_reqid_used(server, reqid) then 
		eno = -1
		msg = "reqid reused"
		rxd.ban_counter_incr(server, cip)
	end

	if not rxd.is_time_valid(time) then
		eno = -1
		msg = "invalid time"
		rxd.ban_counter_incr(server, cip)
	end
	
	-- read req header
	ehdr, eno = sock.read(cso, rxcore.HDRLEN)
	if not ehdr then msg = "reading ehdr"; goto cerror end
	
	--unwrap req header (ctr=0)
	datalen, code, arg = rxcore.unwrap_hdr(server.key, reqid, 0, ehdr)
	if not datalen then 
		msg = "header decrypt error"
		rxd.ban_counter_incr(server, cip)
		eno = -1
		goto cerror
	else
		-- header is valid (the header has been properly 
		-- decrypted, so the client is assumed to be genuine.)
		-- => reset the ban try counter for the client ip
		rxd.ban_counter_reset(server, cip)
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
	rcode, rarg, rdata = rxd.handle_req(reqid, code, arg, data)
	
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
	log(strf("client %s %d: errno: %d  (%s)", cip, cport, eno, msg))
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
	server = server or rxd.server
	init_ban_list(server)
	init_used_reqid_list(server)
	server.bind_sockaddr = server.bind_sockaddr or 
		sock.make_ipv4_sockaddr(server.bind_addr, server.port)
	sso, msg = sock.bind(server.bind_sockaddr)
	rxd.log("server bound to %s port %d", server.bind_addr, server.port)
	
	local r, exitcode
	while not r do
		cso, eno = sock.accept(server)
		if not cso then
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
end--serve()


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
	local tmpdir = server.tmpdir or '.'
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
rxd.server.max_time_drift = 300 -- max secs between client and server time
rxd.server.ban_max_tries = 3  -- number of tries before being banned
rxd.server.log_rejected = true 
rxd.server.log_aborted = true
rxd.server.debug = true
rxd.server.log_already_banned = true
rxd.server.tmpdir = os.getenv"$TMP" or "/tmp"

-- load config
local conf = require "rxconf"

-- copy conf values in server
for k,v in pairs(conf) do rxd.server[k] = v end
conf = nil -- conf is no longer needed

-- run the server
-- os.exit(rxd.serve())

-- serve() return value can be used by a wrapping script to either
-- stop or restart the server. convention is to restart server if 
-- exitcode is 0.

return rxd


