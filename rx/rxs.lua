-- Copyright (c) 2022  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 	rx server

220309 
	split server, client code  (older code: see rx10.lua)

]]
	
local VERSION = "rx11-220310"
------------------------------------------------------------------------
-- imports and local definitions

local util = require "util"
local sock = require 'ssock'  -- stream sockets

local errm = util.errm
local strf, repr = string.format, util.repr
local spack, sunpack = string.pack, string.unpack

local lastlogline = ""

local function log(msg)
	local line = strf("LOG: %s %s", util.isots(), msg)
	-- dont fully repeat identical lines
	if line == lastlogline then 
		print("*") 
	else 
		print(line)
		lastlogline = line
	end
end

------------------------------------------------------------------------
-- rx encryption

local lm = require 'luamonocypher'

local KEYLEN = 32
local NONCELEN = 24
local MACLEN = 16
local EHDRLEN = 32  

local function encrypt(key, nonce, m, ctr)
	-- encrypt m with key, nonce, ctr
	-- return the encrypted message c 
	-- => #c = #m + MACLEN
	return lm.encrypt(key, nonce, m, ctr)
end

local function decrypt(key, nonce, c, ctr)
	-- return decrypted message or nil errmsg if MAC error
	return lm.decrypt(key, nonce, c, ctr)
end

local randombytes = lm.randombytes

------------------------------------------------------------------------
-- nonce

local function keyreqp(nonce)
	-- return true if nonce for keyreq (ends with \x01)
	return (nonce:byte(NONCELEN) == 1)
end

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

local function cmd_summary(cmd)
	cmd = cmd:gsub("^%s*", "") -- remove leading space and nl
	cmd = (cmd:match("^(.-)\n")) or cmd -- get first line
	local ln = 40
	if #cmd > ln then 
		cmd = cmd:sub(1, 37) .. "..."
	end
	return cmd
end
	

------------------------------------------------------------------------
--server

local function handle_cmd(cmd, input, server)
	-- return rcode, rdata
	local rcode, rdata = 0, ""
	local r, msg
	
	if cmd == "KEYREQ" then
		return 0, server.tpk
	end
	if cmd == "MUSTEXIT" then
		server.mustexit = 1
		return 0, "exiting..."
	end
	if cmd == "TESTERROR" then
		error("testerror")
		return 1, "testerror..."
	end
	util.fput("f0", input)
	local fh, msg = io.popen(cmd)
	if not fh then 
		return 127, msg
	end
	rdata = fh:read("a")
	local r, exit, status = fh:close()
	-- same convention as he.shell: return exitcode or
	-- signal number + 128
	rcode = (exit=='signal' and status+128 or status)
	return rcode, rdata
end--handle_req

local function serve_client(server, cso)
	local nonce, ehdr, edata, er
	local keyreqflag
	local key
	local hdr
	local data = ""
	local rnd, time, code, len
	local rcode, rdata
	local r, err, step 
	local version, cmd, input
	
--~ log(strf("serving %s %s", cso.ip, cso.port))
	
	step = "read nonce"
	nonce, err = sock.read(cso, NONCELEN)
	if not nonce  then goto cerror  end
	keyreqflag = keyreqp(nonce)
	key = keyreqflag and server.mpk or server.key 
	
	step = "read hdr"
	ehdr, err = sock.read(cso, EHDRLEN)
	if not ehdr then goto cerror end
	
	step = "unwrap hdr"
	hdr = decrypt(key, nonce, ehdr, 0)
	if not hdr then
		err = 22 -- EINVAL
		goto cerror
	end
	rnd, time, code, len = sunpack("<I4I4I4I4", hdr)
	-- assume the header is well-formed since it decrypted.
	
	step = "check req time"
	if not is_time_valid(server, time) then
		err = 22 -- EINVAL
		goto cerror
	end

	step = "check data len"
	if len <= 0 then 
		err = 71 -- EPROTO
		goto cerror
	end
	
	step = "read data"
	edata, err = sock.readbytes(cso, len+MACLEN)
	if not edata then goto cerror end
	
	step = "unwrap data"
	data, msg = decrypt(key, nonce, edata, 1)
	if not data then err = 22; goto cerror end

	step = "open data"
	r, version, cmd, input = pcall(sunpack, "<s1s4s4", data)
	if not r then 
		err = 71 --EPROTO
		goto cerror
	end
	if keyreqflag then 
		-- ignore actual cmd and input
		-- (with keyreq encryption, server should only do this)
		cmd = "KEYREQ"
		input = ""
	end
	
	-- handle command and send response
	log(strf("%s VRQ %s", cso.ip, cmd_summary(cmd)))
	rcode, rdata = handle_cmd(cmd, input, server)

	len = #rdata  -- maybe empty string but not nil
	hdr = spack("<I4I4I4I4", rnd, time, rcode, len)
	er = encrypt(key, nonce, hdr, 2) --ctr=2
	if len > 0 then 	
		er = er .. encrypt(key, nonce, rdata, 3) --ctr=3
	end	

	step = "send resp"
	r, err = sock.writeall(cso, er)
	if not r then 
		goto cerror
	else
		sock.close(cso)
		return true
		-- keep 'return' here. It must be the LAST statement
		-- of a block.
	end

	::cerror::
	sock.close(cso)
	msg = errm(err, step)
	log(strf("%s ERR %s ", cso.ip, msg))
	return nil, msg
end--serve_client


local function runserver(server)
	-- server main loop:
	-- 	wait for a client
	--	call serve_client() to process client request
	--	rinse, repeat
	local cso, sso, r, eno, msg
	local family, addr, port
	-- bind server
	local ssa = sock.sa(server.bind_addr, server.port)
	sso, eno, msg = sock.sbind(ssa)
	if not sso then
		msg = util.errm(eno, "bind server")
		log(msg)
		return nil, msg
	end
	log(strf("server %s bound to %s port %s", VERSION,
		 server.bind_addr, server.port ))
	while not server.mustexit do
		cso, eno = sock.accept(sso)
		if not cso then
			log(errm("server accept", eno))
		else
			family, port, ip = sock.sa4_split(cso.sa)
			cso.port, cso.ip = port, sock.ip4tos(ip)
			assert(family, cso.port)--2nd arg
			assert(sock.settimeout(cso, 5000))
			r, msg = serve_client(server, cso) 
--~ 			if not r then
--~ 				log(strf("serve_client: %s", msg))
--~ 			end
		end
	end--while
	log("server exiting")
	sock.close(sso)
end--runserver

local function serverinit(server)
	-- check and initialize server object for a client
	local default = {
		-- default configuration
		
		-- max secs between client and server time
		max_time_drift = 300,  
		
		bind_addr = "0.0.0.0", 
		port = 4096,

		log_rejected = true, 
		log_aborted = true,
		debug = true,	
	}
	-- copy defaults if not already defined in server
	for k,v in pairs(default) do
		-- "== nil" because server values may be set to false
		if server[k] == nil then 
			server[k] = v
		end
	end
	
	if not server.mpk then return nil, "missing mpk" end
	
	-- generate temp keypair (used for key exchange)
	local tsk = lm.randombytes(32)
	local tpk = lm.public_key(tsk)
	local key = lm.key_exchange(tsk, server.mpk)
	tsk = nil -- tsk is no longer needed
	server.key = key
	server.tpk = tpk
--~ print("server key, tpk")
--~ util.px(key)
--~ util.px(tpk)
	return server
end--serverinit



------------------------------------------------------------------------
-- the rxs module

local rxs = {

	runserver = runserver,
	serverinit = serverinit,

	VERSION = VERSION,
}--rxs

return rxs


