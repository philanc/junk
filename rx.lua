-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rx

includes former rxc, rxd, rxcore in one file.

can be required as a library (incl public functions from rxc, rxd, rxcore)
or can be run as a server, with the "serve" argument

	slua rx.lua serve

protocol versions:
	
v0.8
	ban system removed
	handler table replaced with one handler function

v0.7
	- same header for req and resp (32 bytes)
	- the first header block is prefixed by a nonce.

v0.6
	- removed time-based key diversification
	- same header for req and resp (48 bytes)
	- headers and data blocks are prefixed by a nonce.


protocol elements

	rx follows a client/server model: the client sends a request 
	to the server; for each request, the server sends back one response.
	
	request and response have the same structure: a fixed-size 
	header (hdr) followed by an optional variable-length 
	data block (data). The length of the data block is included 
	in the header. If the length ('len') is zero, there is 
	no data block.
	
	header and data are encrypted separately but with the same key.
	It uses authenticated symmetric encryption. This version is 
	based on Morus but the algorithm can be swapped with 
	any other authenticated encryption algo.

	hdr	header (fixed size - encrypted: 32 bytes)

		- rnd(12)   :: string - used to fuzz the header
		- len(4)    :: int32  - unencrypted data size
	
	
	encrypted header and data blocks end with a MAC(16). 
	A nonce(16) is prefixed to the request encrypted header 

	nonce structure:
		- nonce(16) :: reqid(15) .. ctr(1)
		- reqid(15) :: time(4) .. rnd(11) - must be unique
		- ctr(1)    :: small int(0..3) used to make distinct nonces
			       for all encrypted elements
	
	The main part of the nonce is the request id ('reqid'). It is the 
	same reqid that is used for the request and the response headers 
	and data block. The nonce is completed by a one-byte counter that
	ensures that all the blocks use a different nonce.
	
	The ctr value must be the following:
		request header   0	  
		request data     1
		response header  2
		response data    3
		
naming convention:
	'q' query/request
	'r' response
	'hdr'  request or response header block
	'e' encrypted (eg. ehdr, or edata)

]]

local VERSION = "0.8"
------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks

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
local rx -- the rx module object (defined later)

------------------------------------------------------------------------
-- common rx utilities (rxcore)

------------------------------------
-- encryption
local hezen = require 'he.zen'

local KEYLEN = 32
local NONCELEN = 16
local MACLEN = 16
local HDRLEN = 32   	-- encrypted header length (nonce not included)
			-- = #rnd(=12) + #data(=4) + #mac(=16)

-- here, should add crypto selection code (use plc if luazen not avail)

local function encrypt(key, nonce, m)
	-- encrypt m with key, nonce
	-- return the encrypted message c 
	-- => #c = #m + MACLEN
	return hezen.morus_encrypt(key, nonce, m)
end

local function decrypt(key, nonce, c)
	-- return decrypted message or nil errmsg if MAC error
	return hezen.morus_decrypt(key, nonce, c)
end

local function randombytes(n)
	return hezen.randombytes(n)
end

------------------------------------
-- nonce util

local function make_noncelist(time, rnd)
	-- create a list of four distinct nonces used to encrypt/decrypt 
	-- the header and data blocks for the request and the response
	local nl = {}
	time = time or os.time()
	rnd = rnd or randombytes(11)
	for i = 1, 4 do
		table.insert(nl, spack("<I4c11i1", time, rnd, i))
	end
	return nl
end

local function parse_nonce(n)
	-- parse a nonce, extract the time, the random string 
	-- and the counter 
	local time, rnd, ctr = sunpack("<I4c11i1", n)
	return time, rnd, ctr
end



------------------------------------------------------------------------
-- header and data encryption/decryption

local function wrap_hdr(key, nonce, datalen)
	-- a random string is included to make known plaintext attacks harder
	local rnd = randombytes(12)
	local hdr = spack("c12<i4", rnd, datalen)
	local ehdr = encrypt(key, nonce, hdr)
	return ehdr
end

local function unwrap_hdr(key, nonce, ehdr)
	-- decrypt a header, return the data length
	local hdr, err = decrypt(key, nonce, ehdr)
	if not hdr then return nil, "unwrap_header: " .. err end
	local rnd, len = sunpack("c12<i4", hdr)
	return len
end

local function wrap_data(key, nonce, data)
	local edata = encrypt(key, nonce, data)
	return edata
end

local function unwrap_data(key, nonce, edata)
	local data, err = decrypt(key, nonce, edata)
	if not data then return nil, "unwrap_data: " .. err end
	return data
end

local function wrap_req(key, data)
	-- return the encrypted header, the encrypted data, the list
	-- of nonces for the request and the response.
	data = data or ""
	local nl = make_noncelist()
	local ehdr = wrap_hdr(key, nl[1], #data)
	local edata = wrap_data(key, nl[2], data)
	return ehdr, edata, nl
end

local function wrap_resp(key, nl, data)
	data = data or ""
	local ehdr = wrap_hdr(key, nl[3], #data)
	-- here, nonce is NOT prepended to ehdr
	local edata = wrap_data(key, nl[4], data)
	return ehdr, edata
end

-----------------------------------------------------------------------
-- client functions

function request(server, reqt)
	-- return rt or nil, eno, msg
	-- reqt is the request table
	-- rt is the response table
	data = hpack(reqt)
	local sso, r, eno, msg
	local len = #data
	local key = server.key
	local ehdr, edata, nl = rx.wrap_req(key, data)
	--
	-- connect to server
	local sockaddr = server.sockaddr 
		or sock.sockaddr(server.addr, server.port)
	sso, eno = sock.sconnect(sockaddr)
	if not sso then return nil, eno, "connect" end
	
	-- declare local before goto to prevent
	-- "jumps into the scope of local" error
	local rlen, rdata, rt
	
	--
	-- send 1st nonce and header
	r, eno = sock.write(sso, nl[1] .. ehdr)
	if not r then msg = "send header"; goto ioerror end
	-- send data
	r, eno = sock.write(sso, edata)
	if not r then msg = "send data"; goto ioerror end
	-- recv response header
	ehdr, eno = sock.read(sso, rx.HDRLEN)
	if not ehdr then msg = "recv header"; goto ioerror end
	rlen, msg= rx.unwrap_hdr(key, nl[3], ehdr)
	if not rlen then
		eno = -1
		goto ioerror
	end
	
	-- recv resp data
	edata, eno = sock.read(sso, rlen + rx.MACLEN)
	if not edata then msg = "recv data"; goto ioerror end
	rdata, msg = rx.unwrap_data(key, nl[4], edata)
	if not rdata then 
		eno = -1
		msg = "unwrap rdata"
		goto ioerror 
	end
	rt, msg = hunpack(rdata)

	do -- this do block because return MUST be the last stmt of a block
	return rt, msg
	end
	
	::ioerror::
	sock.close(sso)
	return nil, eno, msg
end

------------------------------------------------------------------------
-- client functions:  remote execution commands

local function lua(server, luacmd, desc, reqt)
	-- run a lua chunk in the server environment (beware!!)
	-- desc is an optional command short description (for logging)
	-- reqt is the request table. if not provided it is created.
	-- it is serialized and passed to the lua chunk on the server.
	-- the chunk should return a response table
	--
	reqt = reqt or {}
	reqt.desc = reqt.desc or desc
	reqt.lua = luacmd
	local rt, eno, msg = rx.request(server, reqt)
	if not rt then 
		msg = strf("rx error %s (%s)", tostring(eno), tostring(msg))
		return {ok=false, errmsg=msg}
	end
--~ 	print("RT="); he.pp(rt)
	return rt
end

local function sh(server, shcmd, desc)
	local reqt = {shcmd = shcmd, desc = desc, }
	luacmd = [[
		local reqt = ...
		require'he.i'
		local rt = {}
		local cmd = reqt.shcmd
		local fh, msg = io.popen(cmd)
		if not fh then return {errmsg = msg} end
		local content = fh:read("a")
		local r, exit, status = fh:close()
		rt.content = content
		-- same convention as he.shell: return exitcode or
		-- signal number + 128
		rt.status = (exit=='signal' and status+128 or status)
		return rt
		]]
	local rt, msg
	rt = rx.lua(server, luacmd, desc, reqt)
	return rt.content, rt.errmsg
end --sh()	

local function download(server, filename)
	local reqt = {}
	reqt.filename = filename
	reqt.desc = "download" .. filename
	cmd = [[
		local reqt = ...
		require'he.i'
		local rt = {}
		local r, msg = he.fget(filename)
		if not r then
			rt.ok = false
			rt.errmsg = msg
		else 
			rt.ok = true
			rt.content = t
		end
		return rt
		]]
	local rt, msg
	rt = rx.lua(server, cmd, reqt)
	return rt.content, rt.errmsg
end --download()






-----------------------------------------------------------------------
-- server functions:  anti-replay and other utilities

	
local function init_used_nonce_list(server)
	-- ATM, start with empty list
	server.nonce_tbl = {}
end
	
local function is_nonce_used(server, nonce)
	-- determine if nonce has recently been used
	-- then set it to used
	local  r = server.nonce_tbl[nonce]
	server.nonce_tbl[nonce] = true
	return r
end


-- max valid difference between request time and server time
-- defined in server server.max_time_drift
--
local function is_time_valid(server, reqtime)
	return math.abs(os.time() - reqtime) < server.max_time_drift
end


local function rerr(msg, ctx, rt)
	-- return a rdata with an error msg 
	-- ctx is an additional message to give the error context
	rt = rt or {}
	ctx = ctx or ""
	rt.ok = false
	rt.errmsg = strf("%s: %s", msg, ctx)
	log("handle_req error: " .. rt.errmsg)
	return hpack(rt)
end

local function handle_req(data, nonce, cip, cport)
	-- return rdata
--~ 	ppp('handle_req', repr(data))
	local dt, rt, msg, r
	local chunk, luafunc
	rt = {ok = true}
	dt, msg = hunpack(data)
	if not dt then return rerr(msg, "unpack data") end
	if type(dt) == "string" then 
		return strf("rx time: %s  echo: %s", he.isodate(), dt)
	end
	if type(dt) ~= "table" then 
		return rerr("invalid data content", "handle_req") 
	end
	dt.nonce = nonce
	dt.cip = cip
	dt.cport = cport
	local desc = dt.desc or ("n=" .. he.stohex(nonce))
	log(strf("%s %d: %s", cip, cport, desc))
	if dt.exitcode then
		return rerr("exitcode=" .. dt.exitcode, "handle_req"), 
			dt.exitcode
	end
	if dt.lua then
		-- dt.lua is a lua cmd. load it as a lua chunk, 
		-- then call it with dt as an argument
		-- in the lua cmd, dt can be accessed as: 
		--	local dt = ...
		-- the lua cmd should return a "result table" rt as:
		--	local rt = { . . . }
		--	return rt
		--
		luafunc, msg = load(dt.lua)
		if not luafunc then 
			return rerr(msg, "loading lua cmd")
		end
		r, rt, msg = pcall(luafunc, dt)
		if not r then
			-- an error has occurred
			msg = rt
			return rerr(msg, "lua cmd error")
		end
		if not rt then 
			return rerr(msg, "in lua cmd")
		end
		return hpack(rt), rt.exitcode
	end
		
	return rerr("nothing to do", "handle_req")
	
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
	local exitcode
	
	-- read nonce
	nonce, eno = sock.read(cso, rx.NONCELEN)
	if not nonce then msg = "reading nonce"; goto cerror end
	reqtime, rnd, ctr = rx.parse_nonce(nonce)
--~ ppp('got nonce', #nonce)
	nonces = rx.make_noncelist(reqtime, rnd)
	nonce = nonces[1] 	-- << this is on purpose:
			-- to prevent an attacker to bypass anti-replay
			-- with an initial nonce with ctr > 4
			-- (keep using nonces[1] for anti-replay.)
	
	if is_nonce_used(server, nonce) then 
		eno = -1
		msg = "REJECTED/nonce reused"
		goto cerror
	end

	if not is_time_valid(server, reqtime) then
		eno = -1
		msg = "REJECTED/invalid time"
		goto cerror
	end

--~ ppp'get hdr'
	-- read req header
	ehdr, eno = sock.read(cso, rx.HDRLEN)
	if not ehdr then msg = "reading ehdr"; goto cerror end
--~ ppp("#ehdr", #ehdr)
	--unwrap req header 
	datalen = rx.unwrap_hdr(server.key, nonces[1], ehdr)
	if not datalen then 
		msg = "REJECTED/decrypt error"
		eno = -1
		goto cerror
	else
		-- header is valid (the header has been properly 
		-- decrypted, so the client is assumed to be genuine.)
		-- => reset the ban try counter for the client ip
		-- rx.ban_counter_reset(server, cip)
	end
--~ ppp'got hdr, get data'
	
	-- read data
	edata, eno = sock.read(cso, datalen + rx.MACLEN)
	if not edata then msg = "reading edata"; goto cerror end
	-- unwrap data
	data, msg = rx.unwrap_data(server.key, nonces[2], edata)
	if not data then
		eno = -1
		-- msg is set above
		goto cerror
	end
	
	-- don't log here
 	--log(strf("%s %d: req=%s", cip, cport, he.stohex(nonces[1])))

	-- handle the request
	-- nonce is passed to the request to be used as a uid if needed
	-- cip, cport are passed for logging
	rdata, exitcode = handle_req(data, nonce, cip, cport)
	
	-- send the response
	rhdr, rdata = rx.wrap_resp(server.key, nonces, rdata)

--~ ppp'send rhdr'
	r, eno = sock.write(cso, rhdr)
	if not r then msg = "sending rhdr"; goto cerror end
--~ ppp('send rdata')
	r, eno = sock.write(cso, rdata)
	if not r then msg = "sending rdata"; goto cerror end
	
	do  -- this do block because return MUST be the last stmt of a block
		return exitcode
	end

	::cerror::
	sock.close(cso)
	log(strf("%s %d: eno=%d (%s)", cip, cport, eno, msg))
	return nil

end --serve_client()

------------------------------------------------------------------------
-- the server main loop

local function serve(server)
	-- server main loop:
	-- 	wait for a client
	--	call serve_client() to process client request
	--	rinse, repeat
	local cso, sso, r, eno, msg
	init_used_nonce_list(server)
	server.bind_sockaddr = server.bind_sockaddr or 
		sock.sockaddr(server.bind_addr, server.port)
	sso, msg = sock.sbind(server.bind_sockaddr)
	rx.log("server bound to %s port %d", server.bind_addr, server.port)
	
	local exitcode
	while not exitcode do
		cso, eno = sock.accept(sso)
		if not cso then
			rx.log("rx.serve: accept error:", eno)
		else
			assert(sock.timeout(cso, 5000))
			exitcode = serve_client(server, cso) 
		end
	end--while
	if cso then sock.close(cso); cso = nil end
	-- TODO should be: 	close_all_clients(server)
	local r, msg = sock.close(sso)
	rx.log("server closed", r, msg)
	return exitcode
end--serve()


------------------------------------------------------------------------
-- the rx module
rx = {
	-- core
	make_noncelist = make_noncelist,  -- ([time]) => noncelist
	parse_nonce = parse_nonce, -- (nonce) => time, rnd, ctr
	new_reqid = new_reqid,     -- () => rid
	get_nonce = get_nonce,     -- (ehdr|edata) => rid
	make_nonce = make_nonce,   -- (rid, ctr) => nonce
	wrap_hdr = wrap_hdr,       -- (k, nonce, len) => ehdr
	wrap_data = wrap_data,     -- (k, nonce, data) => edata
	unwrap_hdr = unwrap_hdr,   -- (k, nonce, ehdr) => len
	unwrap_data = unwrap_data, -- (k, nonce, edata) => data
	wrap_req = wrap_req,       -- (k, data) => ehdr, edata, noncelist
	wrap_resp = wrap_resp,     -- (k, noncelist, data) => ehdr, edata

	HDRLEN = HDRLEN,
	MACLEN = MACLEN,
	NONCELEN = NONCELEN,
	
	RESTART = 0,
	SHUTDOWN = 1,

	VERSION = VERSION,
	
	-- server
	serve = serve,             -- (server) => exitcode
	
	-- client
	request = request,
	lua = lua,
	sh = sh,
	download = download,

}--rx module


------------------------------------------------------------------------
-- run server

if arg[1] and arg[1] == "serve" then
	-- default functions
	rx.log = log
	rx.server = {}

	-- set default server parameters
	rx.server.max_time_drift = 300  -- max secs between client 
					-- and server time
	rx.server.log_rejected = true 
	rx.server.log_aborted = true
	rx.server.debug = true
	rx.server.tmpdir = os.getenv"$TMP" or "/tmp"

	-- load config
	local conf = require "rxconf"

	-- copy conf values in server
	for k,v in pairs(conf) do rx.server[k] = v end
	conf = nil -- conf is no longer needed

	-- run the server
	local exitcode = rx.serve(rx.server)
	print("EXITCODE:", exitcode)
	os.exit(exitcode)

	-- serve() return value can be used by a wrapping script to either
	-- stop or restart the server. convention is to restart server if 
	-- exitcode is 0.
end --if serve

--~ he.pp(rx)

return rx


