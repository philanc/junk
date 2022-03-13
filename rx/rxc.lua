-- Copyright (c) 2022  Phil Leblanc  -- see LICENSE file

--[[  rx11 client

220310 
	client-side extracted from rx10.lua
	removed clientinit(). server parameters are setup by application.
		(see rxc1.lua sample app)


]]
------------------------------------------------------------------------

local VERSION = "rx11-220310 "
------------------------------------------------------------------------
-- imports and local definitions

local util = require "util"

local sock = require 'ssock'  -- stream sockets

local ppp=print
local traceback = require("debug").traceback
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
local rx -- the rx module object (defined later)

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
-- header and data encryption/decryption

local function newnonce(keyreqflag)
	local nonce = randombytes(NONCELEN)
	if keyreqflag then
		-- ensure nonce ends with 0x01
		nonce = nonce:gsub(".$", "\x01")
	else
		-- emsure nonce doesn't
		nonce = nonce:gsub("\x01$", "\x00")
	end
	return nonce
end

local function keyreqp(nonce)
	-- return true if nonce for keyreq (ends with \x01)
	return (nonce:byte(NONCELEN) == 1)
end


-----------------------------------------------------------------------
-- client functions

local function request(server, cmd, input, keyreqflag)
	-- return rcode, rdata or nil, msg
	-- in case of  communication error, return nil, errmsg
	-- in case of  request handler error at the server, the function 
	-- should return a valid non-zero code (and maybe some error 
	-- msg in rdata)
	input = input or ""
	local sso, r, err, step
	local data = spack("<s1s4s4", "rx10", cmd, input)
	local key = keyreqflag and server.mpk or server.key
	
	if not key then return nil, "key missing" end
	
	-- wrap request
	local nonce = newnonce(keyreqflag)
	local rnd = sunpack("<I4", randombytes(4))
	local time = os.time()
	local code = 0
	local len = #data
	local hdr = spack("I4I4I4I4", rnd, time, code, len)
	local eq = nonce 
		.. encrypt(key, nonce, hdr,  0) --ctr=0
		.. encrypt(key, nonce, data, 1) --ctr=1
	--
	-- declare local before goto to prevent
	-- "jumps into the scope of local" error
	local edata, ehdr, sso

--~ print("request()", keyreqflag)
	step = "connect to server"
	local sockaddr = server.sockaddr 
		or sock.sa(server.addr, server.port)
	sso, err = sock.sconnect(sockaddr)
	if not sso then goto ioerror end
		
	step = "send ereq"
	r, err = sock.writeall(sso, eq)
	if not r then goto ioerror end
	
	-- now get response
	
	step = "read rhdr"
	ehdr, err = sock.read(sso, EHDRLEN)
	if not ehdr then goto ioerror end
	
	step = "unwrap rhdr"
	hdr = decrypt(key, nonce, ehdr, 2)
	if not hdr then
		err = 22 -- EINVAL
		goto ioerror
	end
	rnd, time, code, len = sunpack("<I4I4I4I4", hdr)
	-- assume the header is well-formed since it decrypted.

	if len == 0 then -- no rdata block
		sock.close(sso)
		return code, "" 
	end
	
	step = "read rdata"
	edata, err = sock.read(sso, len+MACLEN)
	if not edata then goto ioerror end

	step = "unwrap rdata"
	data, msg = decrypt(key, nonce, edata, 3)
	if not data then err = 22 ; goto ioerror end
	
	do
		sock.close(sso)
		return code, data
	end
	
	::ioerror::
	if sso then sock.close(sso) end
	
	return nil, errm(err, step)
end--request()

local function refreshkey(server)
	local rcode, rdata
	rcode, rdata = request(server, "REQKEY", "", true)
	if not rcode or rcode ~= 0 then
		return nil, rdata
	end
	local tpk = rdata
	local key = lm.key_exchange(server.msk, tpk)
	assert(key, "key_exchange error")
	server.key = key
--~ util.px(tpk, "tpk")
--~ util.px(key, "key")
	return true
end

------------------------------------------------------------------------

local function clientinit(server)
	-- check and initialize server object for a client

	if not server.msk then error("msk missing") end
	if not server.mpk then
		server.mpk = lm.public_key(server.msk)
	end
	return server
end--clientinit



------------------------------------------------------------------------

local rxc = {

	request = request,
	refreshkey = refreshkey,
	clientinit = clientinit,

	VERSION = VERSION,
}--rxc

return rxc