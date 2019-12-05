-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxd



v0.8
	ban system removed
	handler table replaced with one handler function

]]

------------------------------------------------------------------------
-- tmp path adjustment
--~ package.path = "../he/?.lua;" .. package.path

------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks
local hezen = require 'he.zen'
local hepack = require 'he.pack'
local sock = require 'l5.sock'

local ppp=print

local traceback = require("debug").traceback

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack
local hpack, hunpack = hepack.pack, hepack.unpack

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end


local function log(fmt, ...)
	print("LOG: " .. he.isodate(), strf(fmt, ...))
end


------------------------------------------------------------------------
-- common rx utilities

local rxcore = require "rxcore"



-----------------------------------------------------------------------
rxd = {  -- the rxd module
	log = log,
	server = {},	-- the server object
}


-----------------------------------------------------------------------






-----------------------------------------------------------------------
-- server - anti-replay and other utilities


	
function rxd.init_used_nonce_list(server)
	-- ATM, start with empty list
	server.nonce_tbl = {}
end
	
function rxd.is_nonce_used(server, nonce)
	-- determine if nonce has recently been used
	-- then set it to used
	local  r = server.nonce_tbl[nonce]
	server.nonce_tbl[nonce] = true
	return r
end


-- max valid difference between request time and server time
-- defined in server server.max_time_drift
--
function rxd.is_time_valid(server, reqtime)
	return math.abs(os.time() - reqtime) < server.max_time_drift
end


local function rerr(msg, ctx, rt)
	-- return a rdata with an error msg 
	-- ctx is an additional message to give the error context
	rt = rt or {}
	ctx = ctx or ""
	rt.ok = false
	rt.errmsg = strf("%s: %s", ctx, rt)
	return hpack(rt)
end

function rxd.handle_req(data)
	-- return rdata
	ppp('handle_req', repr(data))
	local dt, rt, msg
	rt = {ok = true}
	dt, msg = hunpack(data)
	if not dt then return rerr(msg, "unpack data") end
	if type(dt) == "string" then 
		return strf("rxd time: %s  echo: %s", he.isodate(), dt)
	end
	if type(dt) ~= "table" then return rerr("invalid data content", "handle_req") end
	-- here 
	if dt.lua then
		-- execute lua cmd
	elseif dt.sh then
		-- execute sh cmd
	else 
		return rerr("nothing to do", "handle_req")
	end
end


local function serve_client(server, cso)
	-- return false, exitcode to request the server loop to exit. 
	--   the exitcode value can be use to ask the server to shudown 
	--   or to restart.
	
	local csa = sock.getpeername(cso) -- get client sockaddr
	local cip, cport = sock.sockaddr_ip_port(csa)
	
	local r, eno, msg
	local nonce, ehdr, edata, hdr, data
	local nonce, reqtime, rnd, ctr, nonces
	local datalen
	local handler, rcode, rarg, rdata
	
	-- read nonce
	nonce, eno = sock.read(cso, rxcore.NONCELEN)
	if not nonce then msg = "reading nonce"; goto cerror end
	reqtime, rnd, ctr = rxcore.parse_nonce(nonce)
ppp'got nonce'
	nonces = rxcore.make_noncelist(time, rnd)
	nonce = nonces[1] 	-- << this is on purpose:
			-- to prevent an attacker to bypass anti-replay
			-- with an initial nonce with ctr > 4
			-- (keep using nonces[1] for anti-replay.)
	
	if rxd.is_nonce_used(server, nonce) then 
		eno = -1
		msg = "nonce reused"
		goto cerror
	end

	if not rxd.is_time_valid(server, reqtime) then
		eno = -1
		msg = "invalid time"
		goto cerror
	end

ppp'get hdr'
	-- read req header
	ehdr, eno = sock.read(cso, rxcore.HDRLEN)
	if not ehdr then msg = "reading ehdr"; goto cerror end
ppp("#ehdr", #ehdr)
	--unwrap req header 
	datalen = rxcore.unwrap_hdr(server.key, nonces[1], ehdr)
	if not datalen then 
		msg = "header decrypt error"
		eno = -1
		goto cerror
	else
		-- header is valid (the header has been properly 
		-- decrypted, so the client is assumed to be genuine.)
		-- => reset the ban try counter for the client ip
		-- rxd.ban_counter_reset(server, cip)
	end
ppp'got hdr, get data'
	
	-- read data
	edata, eno = sock.read(cso, datalen + rxcore.MACLEN)
	if not edata then msg = "reading edata"; goto cerror end
	-- unwrap data
	data, msg = rxcore.unwrap_data(server.key, nonces[2], edata)
	if not data then
		eno = -1
		-- msg is set above
		goto cerror
	end
	
	log(strf("%s %d: req=%s", cip, cport, he.stohex(nonces[1])))

	-- handle the request
	rdata = rxd.handle_req(data)
	
	-- send the response
	rhdr, rdata = rxcore.wrap_resp(server.key, nonces, rdata)

ppp'send rhdr'
	r, eno = sock.write(cso, rhdr)
	if not r then msg = "sending rhdr"; goto cerror end
ppp('send rdata')
	r, eno = sock.write(cso, rdata)
	if not r then msg = "sending rdata"; goto cerror end
	
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
--~ 	init_ban_list(server)
	rxd.init_used_nonce_list(server)
	server.bind_sockaddr = server.bind_sockaddr or 
		sock.sockaddr(server.bind_addr, server.port)
	sso, msg = sock.sbind(server.bind_sockaddr)
	rxd.log("server bound to %s port %d", server.bind_addr, server.port)
	
	local r, exitcode
	while not r do
		cso, eno = sock.accept(sso)
		if not cso then
			rxd.log("rxd.serve: accept error:", eno)
		else
			assert(sock.timeout(cso, 5000))
			r, exitcode = serve_client(server, cso) 
		end
	end--while
	if cso then sock.close(cso); cso = nil end
	-- TODO should be: 	close_all_clients(server)
	local r, msg = sock.close(sso)
	rxd.log("server closed", r, msg)
	return exitcode
end--serve()

--[==[
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


-- ]==]

------------------------------------------------------------------------
-- run server

-- default functions
rxd.log = log

-- set default server parameters
rxd.server.max_time_drift = 300 -- max secs between client and server time
--~ rxd.server.ban_max_tries = 3  -- number of tries before being banned
rxd.server.log_rejected = true 
rxd.server.log_aborted = true
rxd.server.debug = true
--~ rxd.server.log_already_banned = true
rxd.server.tmpdir = os.getenv"$TMP" or "/tmp"

-- load config
local conf = require "rxconf"

-- copy conf values in server
for k,v in pairs(conf) do rxd.server[k] = v end
conf = nil -- conf is no longer needed

-- run the server
-- os.exit(rxd.serve())

print(rxd.serve())

-- serve() return value can be used by a wrapping script to either
-- stop or restart the server. convention is to restart server if 
-- exitcode is 0.

return rxd


