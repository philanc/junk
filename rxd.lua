-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

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


local function log(...)
--~ 	print(he.isodate():sub(10), ...)
	print(he.isodate(), ...)
end


------------------------------------------------------------------------
-- common rx utilities

local rxcore = require "rxcore"



-----------------------------------------------------------------------
-- the rx server object
-- make it global (so it can be used in conf chunks)
rxd = {}
rxd.handlers = {} -- handler table


-----------------------------------------------------------------------
-- server - ban system and anti-replay and other utilities


local function check_not_banned(client_ip)
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

local function read_request(ctx)
	local ehdr, cmdlen, datalen, ecmd, edata, cmd, data
	ctx.state = "get req hdr"
	ehdr = assert(ctx.client:read(rxcore.EC_HDRLEN))
	assert(#ehdr == rxcore.EC_HDRLEN, "invalid header")
	ctx.reqtime, ctx.nonce = rxcore.get_reqtime_nonce(ehdr)
	assert(time_is_valid(ctx.reqtime), "invalid req time")
	assert(not used_nonce(ctx.nonce), "already used nonce")
	cmdlen, datalen = assert(rxcore.decrypt_reqhdr(ctx, ehdr))
	-- here, req header is valid => client is genuine
	ctx.state = "get req cmd"
	ban_counter_reset(ctx.client_ip)
	cmd, data = "", ""
	if cmdlen > 0 then 
		ecmd = assert(ctx.client:read(cmdlen + rxcore.MACLEN))
		cmd = rxcore.decrypt_cmd(ctx, ecmd)
	end
	if datalen > 0 then 
		edata = assert(ctx.client:read(datalen + rxcore.MACLEN))
		data = rxcore.decrypt_data(ctx, edata)
	end
	return cmd, data
end --read_request()

local function send_response(ctx, status, resp)
	local ehdr, eresp = rxcore.encrypt_resp(ctx, status, resp)
	ctx.state = "send resp hdr"
	assert(ctx.client:write(ehdr))
	if eresp then 
		ctx.state = "send resp"
		assert(ctx.client:write(eresp))
	end	
	return true
end --send_response()

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
	local cmd, data = read_request(ctx)
	local status, resp = handle_cmd(ctx, cmd, data)
	send_response(ctx, status, resp)
end

local function serve_client(client)
	--
	-- get client info
	local client_ip, client_port = hesock.getclientinfo(client, true)
	-- prepare context
	local ctx = { 
		smk = rxd.smk,
		debug = rxd.debug,
		handlers = rxd.handlers,
		client = client,
		client_ip = client_ip,
		client_port = client_port,
	}
	local ok, r, errmsg
	if ctx.debug then 
		ok, r, errmsg = xpcall(try_serve_client, traceback, ctx)
	else
		ok, r, errmsg = pcall(try_serve_client, ctx)
	end
	if not ok then 
		errmsg = tostring(ctx.state) .. ":: " .. tostring(r) .. ":"tostring(errmsg)
		if ctx.state == "get req hdr" then
			-- invalid header
			ban_if_needed(ctx.client_ip)
			rxd.log("REJECTED", ctx.client_ip, errmsg)
		else
			rxd.log("ABORTED", ctx.client_ip, errmsg)
		end
	end
	ctx.client:close()
end

	

------------------------------------------------------------------------
-- the server main loop

local function serve()
	-- server main loop:
	-- 	wait for a client
	--	call serve_client() to process client request
	--	rinse, repeat
	local client, r, msg
	init_ban_list()
	init_used_nonce_list()
	rxd.bind_rawaddr = rxd.bind_rawaddr or 
		hesock.make_ipv4_sockaddr(rxd.bind_addr, rxd.port)
--~ 	print(111, rxd.bind_addr, rxd.port, repr(rxd.bind_rawaddr))
	local server = assert(hesock.bind(rxd.bind_rawaddr))
	rxd.log(strf("server bound to %s port %d", 
		rxd.bind_addr, rxd.port))
--~ 	print("getserverinfo(server)", hesock.getserverinfo(server, true))
	
	while not rxd.exitcode do
--~ 		rxd.exitcode=11
		client, msg = hesock.accept(server)
		if not client then
			rxd.log("rxd serve(): accept error", msg)
		else
			serve_client(client) 
		end
	end--while
	if client then hesock.close(client); client = nil end
	-- TODO should be: 	close_all_clients(rxd)
	local r, msg = hesock.close(server)
	rxd.log("server closed", r, msg)
	return rxd.exitcode
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
rxd.config_filename="./rxd.conf.lua"
local r, msg = rxcore.load_rxd_config(rxd)
if not r then
	rxd.log("rxd load_config error: " .. msg)
	print("rxd load_config error", msg)
	os.exit(2)
end



-- serve() return value can be used by a wrapping script to either
-- stop or restart the server. convention is to restart server if 
-- exitcode is 0.
os.exit(serve())


