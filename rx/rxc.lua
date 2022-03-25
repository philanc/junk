-- Copyright (c) 2022  Phil Leblanc  -- see LICENSE file

--[[  rx15 client

220325	rx15 - replaced sh-cmd, input with lua-cmd, param
	(protocol has not changed since rx10)


]]
------------------------------------------------------------------------

local VERSION = "rx15-220325"
------------------------------------------------------------------------
-- imports and local definitions

local util = require "util"

local sock = require 'ssock'  -- stream sockets

local ppp=print
local traceback = require("debug").traceback
local errm = util.errm

local strf, repr = string.format, util.repr
local spack, sunpack = string.pack, string.unpack

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

local function newnonce(keyreqflag)
	-- nonce last byte is used to distinguish regular requests
	-- and key requests
	local nonce = randombytes(NONCELEN)
	if keyreqflag then
		-- ensure nonce ends with 0x01
		nonce = nonce:gsub(".$", "\x01")
	else
		-- emsure nonce doesn't end with 0x01
		nonce = nonce:gsub("\x01$", "\x00")
	end
	return nonce
end

-----------------------------------------------------------------------
-- client functions

local function request(server, cmd, param, keyreqflag)
	-- return rcode, rdata or nil, msg
	-- in case of  communication error, return nil, errmsg
	-- in case of  request handler error at the server, the function 
	-- should return a valid non-zero code (and maybe some error 
	-- msg in rdata)
	param = param or ""
	local sso, r, err, step
	local data = spack("<s1s4s4", "rx10", cmd, param)
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
	if #ehdr < EHDRLEN then 
		err = 5  -- EIO
		goto ioerror
	end
		
	
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
	if #edata < len+MACLEN then 
		err = 5  -- EIO
		goto ioerror
	end

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
end--refreshkey

local function loadconf(name)
	-- return a server object
	
	local msg
	local confpath = os.getenv("RXPATH") or "./"
	assert((confpath:match("/$")), "rx path must end with '/'")
	name = confpath .. name  .. ".conf"

	local f, err = loadfile(name)
	if not f then
		msg = strf("%s: %s", name, tostring(err))
		return nil, msg
	end
	local server = assert(f())
	server.confpath = confpath

	-- set msk
	server.msk = util.hextos(server.msk)
	server.mpk = util.hextos(server.mpk)
	if server.mpk ~= lm.public_key(server.msk) then
		return nil, "pk matching error"
	end

	-- attempt to get current encryption key
	server.key = util.fget(server.confpath .. server.name .. ".key")
	return server
end--loadconf

------------------------------------------------------------------------

local rxc = {

	request = request,
	refreshkey = refreshkey,
	loadconf = loadconf,

	VERSION = VERSION,
}--rxc

return rxc
