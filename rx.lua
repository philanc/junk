-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rx  - a remote execution server


]]

------------------------------------------------------------------------
-- tmp path adjustment
package.path = package.path .. ";../?.lua"

------------------------------------------------------------------------
-- imports and local definitions

local he = require 'he'
local hefs = require 'hefs'
local hezen = require 'hezen'
local hepack = require 'hepack'

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack
local ssplit = he.split
local startswith, endswith = he.startswith, he.endswith
local pp, ppl, ppt = he.pp, he.ppl, he.ppt

local function repr(x)
	return strf("%q", x) 
end

local function log(...)
	print(he.isodate():sub(10), ...)
end



------------------------------------------------------------------------
-- encryption

local NONCELEN = 16
local MACLEN = 16

local function encrypt(key, nonce, m, ctr)
	-- encrypt m with key, nonce
	-- return the encrypted message c 
	-- => #c = #m + MACLEN
	return hezen.morus_encrypt(key, nonce, m, ctr)
end

local function decrypt(key, nonce, c, ctr)
	-- return decrypted message, nonce or nil errmsg if MAC error
	return hezen.morus_decrypt(key, nonce, c, ctr)
end

local CBLEN = 32
local SBLEN = 16
local ECBLEN = NONCELEN + CBLEN + MACLEN
local ESBLEN = SBLEN + MACLEN


------------------------------------------------------------------------
--[[ rx server

request: a fixed-size (CBLEN) command block 'cb' followed by 
an optional parameter block 'pb'. #pb is contained in cb.

encrypted request:  nonce (NONCELEN) .. encrypted cb (CBLEN) .. mac (MACLEN)
			[ .. encrypted pb .. mac ]

response: a fixed-size (SBLEN) status block 'sb' followed by 
an optional response block 'rb'. #rb is contained in sb.

encrypted response: encrypted sb .. mac  [ .. encrypted rb .. mac ]

the nonces used for pb, sb, rb are respectively nonce+1, nonce+2, nonce+3 

cb :: (cmd << 48 | pblen)(uint64) .. datetime(uint64) .. params(16)
sb :: (status << 48 | rblen)(uint64) .. p2(uint64)  
	=>  CBLEN = 32,  SBLEN = 16

]]



rx = {}

-- bind raw address  (localhost:3090)
rx.localaddr = '\2\0\x0c\x12\127\0\0\1\0\0\0\0\0\0\0\0'
-- bind_address = '::1'    -- for ip6 localhost

-- server state
rx.must_exit = nil  -- server main loop exits if true 
		     -- handlers can set it to an exit code
		     -- convention: 0 for exit, 1 for exit+reload

-- debug_mode
-- true => request handler is executed without pcall()
--	   a handler error crashes the server
rx.debug_mode = true

-- server log function
-- default is to print messages to stdout.
rx.log = log  

------------------------------------------------------------------------
-- utilities

local function is_banned(client_ip)
	-- return true if this ip has been banned

end
	
local function replayed(req)
	-- determine if request has been replayed
	
end

local function reject(req, msg1, msg2)
	-- the request is invalid
	
	-- close the client connection
	return req.client:close()
end

local function abort(req, msg1, msg2)
	-- the request is valid but someting went wrong
	
	-- close the client connection
	return req.client:close()
end

------------------------------------------------------------------------
-- rx server

local function serve_client(client)
	-- process a client request:
	--    get a request from the client socket
	--    call the command handler
	--    send the response to the client
	--    close the client connection
	--    return to the server main loop
	--
	local errmsg
	local ecb, cb, epb, pb, pblen, nonce, erb, p1, p2, r
	local client_ip, client_port = hesock.getclientinfo(client)
	if is_banned(client_ip) then return hesock.close(client) end
	
	local req = {}
	req.client = client
	req.client_ip, req.client_port = client_ip, client_port
	
	local ecb, errmsg = client:read(ECBLEN)
	if (not ecb) or #ecb < ECBLEN then
		return reject(req, "cannot read ecb", errmsg)
	end
	
	req.nonce = ecb:sub(1, NONCELEN)
	cb, errmsg = decrypt(rx.key, req.nonce, ecb, 0)
	if not cb then
		return reject(req, "invalid ecb", errmsg)
	end
	
	req.cmd, req.pblen, req,time, req.params = parse_req(cb)
	if replayed(req) then 
		return reject(req, "replayed request", errmsg)
	end
	
	-- here we assume the request is valid
	rx.log("serve client", req.client_ip, req.client_port)
	
	-- read and decrypt pb if any
	if req.pblen > 0 then
		epb, errmsg = client:read(pblen + MACLEN)
		if not epb then
			return abort(req, "cannot read pb", errmsg)
		end
		-- decrypt ("nonce+1" => same nonce, ctr=1)
		req.pb, errmsg = decrypt(rx.key, req.nonce, epb, 1)
		if not req.pb then
			return abort(req, "invalid pb", errmsg)
		end
	end
	
	-- process the request
	-- the handler should at least set req field status
	handle(req)
	if not req.status then
		return abort(req, "handler failed", req.errmsg)
	end
	
	-- build and send status block (sb)
	p1 = req.status << 48
	if req.rb then p1 = p1 | #req.rb end
	p2 = req.p2 or 0
	sb = spack("<I8I8", p1, p2)
	esb = encrypt(rx.key, nonce, sb, 2)  -- "nonce+2"
	r, errmsg = client:write(esb)
	if (not r) or (r < SBLEN) then
		return abort(req, "send status failed", errmsg)
	end
	
	-- send rb if any
	if req.rb then
		r, errmsg = client:write(req.rb)
		if (not r) or (r < #req.rb) then
			return abort(req, "send rb failed", errmsg)
		end
	end
	
	-- close_connection
	hesock.close(client)
	
	return
end--serve_client()

-- the server main loop
function rx.serve()
	-- server main loop:
	-- 	wait for a client
	--	call serve_client() to process client request
	--	rinse, repeat
	local client, msg
	local server = assert(hesock.bind(rx.localaddr))
	rx.log(strf("hehs bound to %s ", repr(rx.localaddr)))
	while true do
		if rx.must_exit then 
			if client then hesock.close(client); client = nil end
			local r, msg = hesock.close(server)
			rx.log("hehs closed", r, msg)
			local exitcode = rx.must_exit
			rx.must_exit = nil
			return exitcode
		end
		client, msg = hesock.accept(server)
		if not client then
			rx.log("rx.serve(): accept() error", msg)
		elseif rx.debug_mode then 
--~ 			rx.log("serving client", client)
			-- serve and close the connection
			serve_client(client) 
--~ 			rx.log("client closed.", client)
		else
			pcall(serve_client, client)
		end
	end--while
end--server()






------------------------------------------------------------------------


	




------------------------------------------------------------------------
-- run 

rx.key = ('k'):rep(32)

--~ rx.serve()


