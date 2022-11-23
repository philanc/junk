-- Copyright (c) 2022  Phil Leblanc  -- see LICENSE file

local RXVERSION = "rx19-221123"

-- rx19: same as rx18 except it uses slua-1.0 (built with luazen-2.0)

local util = require "util"

skey = util.hextos(skey)

local sock = require 'ssock'  -- stream sockets

local ppp=print
local errm = util.errm
local strf, repr = string.format, util.repr
local spack, sunpack = string.pack, string.unpack

local EPERM = 1
local EIO = 5
local EINVAL = 22

-- rx encryption

local lz = require 'luazen'

local KEYLEN = 32
local NONCELEN = 24
local MACLEN = 16
local HDRLEN = 16	-- req:  entropy(8) reqtime(4) datalen(4)
			-- resp: entropy(8) rcode(4) rdatalen(4)
local EHDRLEN = 32	-- (hdr + mac)

local function encrypt(key, nonce, m, ctr)
	return lz.encrypt(key, nonce, m, ctr)
end

local function decrypt(key, nonce, c, ctr)
	return lz.decrypt(key, nonce, c, ctr)
end

local randombytes = lz.randombytes

local function newnonce()
	return randombytes(NONCELEN)
end

local function wrap_header(key, nonce, x, y, ctr)
	local e = os.clock()
	return encrypt(key, nonce, spack("d<I4I4", e, x, y), ctr)
end

local function unwrap_header(key, nonce, ehdr, ctr)
	local hdr, msg, e, x, y
	hdr, msg = decrypt(key, nonce, ehdr, ctr)
	if not hdr then return nil, msg end
	e, x, y = sunpack("d<I4I4", hdr)
	return x, y
end

local function wrap_data(key, nonce, cmdline, content, ctr)
	local data = spack("<s4s4", cmdline, content or "")
	return encrypt(key, nonce, data, ctr)
end

local function unwrap_data(key, nonce, edata, ctr)
	local data, msg
	data, msg = decrypt(key, nonce, edata, ctr)
	if not data then return nil, msg end
	return data
end

local function ioerror(sso, err, step)
	if sso then sock.close(sso) end
	return nil, errm(err, step)
end	
	

------------------------------------------------------------------------
-- client request


local function request(cmdline, content)
	-- return rcode, rdata or nil, msg
	-- in case of communication error, return nil, errmsg
	-- in case of error at the server, return a non-zero rcode 
	--    (and maybe some error msg in rdata)
	-- in case of success, return 0, rcontent
	-- content defaults to ""
	--
	local sso, r, err, step
	local nonce, ehdr, edata, ereq, rcode, rlen
	
	content = content or ""
	
	-- wrap request
	nonce = newnonce()
	edata = wrap_data(skey, nonce, cmdline, content, 1) --ctr=1
	ehdr = wrap_header(skey, nonce, os.time(), #edata, 0)  --ctr=0
	ereq = nonce .. ehdr .. edata
	
	step = "connect to server"
	local sockaddr = sock.sa(saddr, sport)
	sso, err = sock.sconnect(sockaddr)
	if not sso then return nil, errm(err, step) end

	step = "send ereq"
	r, err = sock.writeall(sso, ereq)
	if not r then return ioerror(sso, err, step) end
	
	-- now get response
	
	step = "read rhdr"
	ehdr, err = sock.read(sso, EHDRLEN)
	if not ehdr then return ioerror(sso, err, step) end
	if #ehdr < EHDRLEN then return ioerror(sso, EIO, step) end
		
	step = "unwrap rhdr"
	rcode, rlen = unwrap_header(skey, nonce, ehdr, 2) -- ctr=2
	if not rcode then return ioerror(sso, rlen, step) end

	if rlen == 0 then -- no rdata block
		sock.close(sso)
		return rcode, "" 
	end
	
	step = "read rdata"
	edata, err = sock.read(sso, rlen)
	if not edata then return ioerror(sso, err, step) end
	if #edata < rlen then return ioerror(sso, EIO, step) end

	step = "unwrap rdata"
	data, msg = unwrap_data(skey, nonce, edata, 3) -- ctr=3
	if not data then return ioerror(sso, msg, step) end
	
	sock.close(sso)
	return rcode, data 
end--request()

------------------------------------------------------------------------
------------------------------------------------------------------------
------------------------------------------------------------------------
-- rx server 


-- config

local max_time_drift = 300 -- 5 min - could be reduced
local bind_addr = "0.0.0.0"

-- log
--	logging goes to stdout. It is redirected as suited by the 
--	launching/monitoring script

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

-- anti-replay

local nonce_tbl = {}

local function init_used_nonce_list()
	-- ATM, start with empty list
	nonce_tbl = {}
end
	
local function is_nonce_used(nonce)
	-- determine if nonce has recently been used
	-- then set it to used
	local  r = nonce_tbl[nonce]
	nonce_tbl[nonce] = os.time()
	return r
end

local function is_time_valid(reqtime)
	return math.abs(os.time() - reqtime) < max_time_drift
end

local function cmd_summary(cmdline, content)
	if content == "" then
		return cmdline
	else
		return strf("%s  #c=%d", cmdline, #content)
	end
end

------------------------------------------------------------------------
-- serve_client

local function scerror(cso, err, step)
	if cso then sock.close(cso) end
	msg = errm(err, step)
	log(strf("%s ERR %s ", cso.ip, msg))
	return nil, msg
end	

local handle_req -- request handler. defined at the end of the file.


local function serve_client(cso)
	local nonce, ehdr, edata, er
	local hdr
	local data = ""
	local entropy, time, len
	local rcode, rdata
	local r, err, step 
	local version, cmdline, content
	
--~ log(strf("serving %s %s", cso.ip, cso.port))
	
	step = "read nonce"
	nonce, err = sock.read(cso, NONCELEN)
	if not nonce  then return scerror(cso, err, step) end
	if #nonce < NONCELEN then return scerror(cso, EIO, step) end
	
	step = "read hdr"
	ehdr, err = sock.read(cso, EHDRLEN)
	if not ehdr then return scerror(cso, err, step) end
	
	step = "unwrap hdr"
	time, len = unwrap_header(skey, nonce, ehdr, 0) -- ctr=0
	-- if not time, len is the errmsg
	if not time then return scerror(cso, len, step) end
	
	step = "check req time"
	if not is_time_valid(time) then return scerror(cso, 1, step) end

	step = "check nonce reuse"
	if is_nonce_used(nonce) then return scerror(cso, 1, step) end

	step = "check data len"
	if len <= 0 then return scerror(cso, 1, step) end
	
	step = "read data"
	edata, err = sock.readbytes(cso, len)
	if not edata then return scerror(cso, err, step) end
	if #edata < len then return scerror(cso, 5, step) end
	
	step = "unwrap data"
	data, msg = unwrap_data(skey, nonce, edata, 1) -- ctr=1
	if not data then return scerror(cso, msg, step) end

	step = "unpack data"
	r, cmdline, content = pcall(sunpack, "<s4s4", data)
	if not r then return scerror(cso, 1, step) end
	
	-- handle command 
	log(strf("%s VRQ %s", cso.ip, cmd_summary(cmdline, content)))
	rcode, rdata = handle_req(cmdline, content)

	-- send response
	
	-- rdata maybe an empty string but not nil
	if #rdata > 0 then
		-- don't use wrap_data here (only for request data)
		edata = encrypt(skey, nonce, rdata, 3) --ctr=3
	else
		edata = ""
	end
	er = wrap_header(skey, nonce, rcode, #edata, 2) --ctr=2
	if #edata > 0 then 
		er = er .. edata
	end	

	step = "send resp"
	r, err = sock.writeall(cso, er)
	if not r then return scerror(cso, EIO, step) end
	sock.close(cso)
	return true
end--serve_client

------------------------------------------------------------------------
-- main server loop

local function runserver()
	-- server main loop:
	-- 	wait for a client
	--	call serve_client() to process client request
	--	rinse, repeat
	local cso, sso, r, eno, msg
	local family, addr, port
	-- bind server
	local ssa = sock.sa(bind_addr, sport)
	sso, eno, msg = sock.sbind(ssa)
	if not sso then
		msg = util.errm(eno, "bind server")
		log(msg)
		return nil, msg
	end
	log(strf("server %s bound to %s port %s", 
		RXVERSION, bind_addr, sport ))
	while true do
		cso, eno = sock.accept(sso)
		if not cso then
			log(errm(eno, "server accept"))
		else
			family, port, ip = sock.sa4_split(cso.sa)
			cso.port, cso.ip = port, sock.ip4tos(ip)
			assert(family, cso.port)--2nd arg
			assert(sock.settimeout(cso, 5000))
			r, msg = serve_client(cso) 
		end
	end--while
	log("server exiting")
	sock.close(sso)
end--runserver
	
------------------------------------------------------------------------
------------------------------------------------------------------------
------------------------------------------------------------------------
-- request handler

local function retvalues(r, msg)
	-- return values to be returned by handle_req
	-- turn (r or nil, errmsg) into rcode, rdata
	if r then 
		return 0, tostring(r) 
	else 
		return 1, msg 
	end
end
		
local function do_shcmd(cmd, arg)
	-- execute cmdline as a shell command in ./f
	-- return rcode, rdata ready to use by handle_req
	local r, msg, rcode, rdata
	cmd = strf("cd ./f\n %s %s </dev/null 2>&1 ", cmd, arg)
	r, msg = util.sh(cmd)
	rcode, rdata = retvalues(r, msg)
	return rcode, rdata
end

-- handle_req is declared local before serve_client()
handle_req = function(cmdline, content)
	-- return rcode, rdata (always return int, str -- no nil)
	local rcode, rdata, r, msg, cmd, arg
	-- chk cmdline is valid:
	--	cmd must be alphanum only
	--	arg must be alphanum or any char in '_.*'
	cmd, arg = cmdline:match("^(%w+) *([%w_%*%.]*)$")
	if not cmd then
		return 98, strf("handle_req: invalid cmdline: %s", cmdline)
	end
--~ print("CMD:", cmd, "ARG:", arg)
	if cmd == "fget" then
		return retvalues(util.fget("./f/" .. arg))
	elseif cmd == "fput" then 
		r, msg = util.fput("./f/" .. arg, content)
		if r then return 0, "" else return 1, msg end
	elseif cmd == "ls" then 
		return do_shcmd(cmd, arg)
	elseif cmd == "ll" then 
		cmd = "ls -l" 
		return do_shcmd(cmd, arg)
	elseif cmd == "du" then 
		cmd = "du -s" 
		return do_shcmd(cmd, arg)
	elseif cmd == "md5" then  
		cmd = "md5sum"
		if arg == "" then arg = "*" end
		return do_shcmd(cmd, arg)
	elseif cmd == "mem" then
		local oc, nc = 0, 0
		-- purge invalid nonces from nonce_tbl 
		local o_tbl = nonce_tbl
		nonce_tbl = {}
		for k,v in pairs(o_tbl) do 
			oc = oc + 1 
			if is_time_valid(v) then
				nc = nc + 1
				nonce_tbl[k] = v
			end
		end
		return 0, strf("used memory=%d  #noncetbl: %d => %d", 
				util.mem(), oc, nc)
	elseif cmd == "log" then
		local log = assert(util.fget("./rxs.log"))
		return 0, log
	elseif cmd == "ping" then
		return 0, strf("%s %s", util.isots(), RXVERSION)
	else 
		return 99, strf("handle_req: unknown cmd: %s", cmd)
	end
end --handle_req


------------------------------------------------------------------------
-- serve_client, runserver


return {
	RXVERSION = RXVERSION,
	request = request,
	runserver = runserver,
}

