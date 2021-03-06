-- Copyright (c) 2017  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[

=== henb  v0.2

171029  v0.2
- simplification of the public interface
- remove hash-based identification of blobs

Client API

newclient([host, port])  => cli
	create a new client object

cli:get(bid)  => blob or nil, err
	return the blob associated with bid

cli:put(bid, blob)  => ok or nil, err  
	store a blob on server with name bid

cli:chk(bid) => bln or nil, err
	return blob length if blob 'bid' exists, or nil, err

cli:del(bid) => ok or nil, err
	delete blob with name bid

cli:nop() => ok or nil, err  
	do nothing (can be used to ping server)

Server API:

serve(server)




]]

local henb = {}
henb.VERSION = "0.2"


local he = require "he"
local hezen = require "hezen"
local hesock = require "hesock"

------------------------------------------------------------------------
-- local definitions


local spack, sunpack = string.pack, string.unpack
local strf = string.format

local log = function(...) print(he.isodate():sub(10), ...) end
local quiet = function(...) return  end



------------------------------------------------------------------------
-- henb module


local function send(so, code, id, content)
	content = content or ""
	id = id or ""
	assert(code == code & 0xff, "code must be one byte")
	assert(#id <= 0xff, "id ln must be one byte")
	local data = spack("<BBI4", code, #id, #content) -- 6 bytes
	if id ~= "" then data = data .. id end
	if content ~= "" then data = data .. content end
	return so:write(data)
end

local function receive(so)
	local hd, msg, code, idln, id, bln, blob
	hd, msg = so:read(6)
	if not hd then return nil, msg end
--~ 	print(he.stohex(hd))
	assert(#hd == 6)
	code, idln, bln = sunpack("<BBI4", hd)
	if idln > 0 then
		id, msg = so:read(idln)
		if not  id then return nil, 'read_id: ' .. msg end
	else
		id = ""
	end
	if bln > 0 then
		blob, msg = so:read(bln)
		if not  blob then return nil, 'read_blob: ' .. msg end
	else
		blob = ""
	end
	return code, id, blob
end --receive()


-- command codes
henb.NOP = 0
henb.GET = 1
henb.PUT = 2
henb.UPD = 3
henb.DEL = 4
henb.CHK = 5
henb.EXIT = 255
--
-- status
henb.OK = 0
henb.UNKNOWN = 1
henb.NOTFOUND = 2
henb.BADHASH = 3
henb.DELERR = 4

------------------------------------------------------------------------
-- client definitions

henb.client = he.class()

function henb.newclient(host, port)
	local cli = henb.client()
	cli.host = host or "localhost"
	cli.port = port or 3091
	return cli
end

function henb.client.cmd(cli, code, id, blob)
	-- send code, id, blob to server (server response is (rcode, rblob)
	-- (id is not used in server responses)
	-- return rblob, or nil, rcode
	local so, msg = hesock.connect(cli.host, cli.port)
	if not so then return nil, msg end
	send(so, code, id, blob)
	local rcode, id, rblob = receive(so)
	hesock.close(so)
	if rcode == 0 then
		return rblob
	else
		return nil, rcode
	end
end--cmd

function henb.client.nop(cli)
	return cli:cmd(henb.NOP, "",  "")
end--nop

function henb.client.exit_server(cli)
	return cli:cmd(henb.EXIT, "", "")
end

function henb.client.put(cli, bid, blob)
	return cli:cmd(henb.PUT, bid, blob)
end

function henb.client.get(cli, bid)
	-- get blob with id 'bid'
	return cli:cmd(henb.GET, bid, "")
end

function henb.client.chk(cli, bid)
	-- check blob identified by bid
	-- return blob ln or nil, henb.NOTFOUND
	local rblob, rcode = cli:cmd(henb.CHK, bid, "")
	if not rblob then return nil, rcode end
	local bln, msg = sunpack("<I4", rblob)
	return bln, msg
end

function henb.client.del(cli, bid)
	return cli:cmd(henb.DEL, bid)
end

------------------------------------------------------------------------
-- server definitions

henb.default_server = {  
	host = "localhost", -- server bind address
	port = '3091',            -- server port
	exit_server = false,  -- set this to true to request the server to exit
	store_path = './',    -- path to dir where blobs are stored 
	                      -- (incl '/' at end)
	--
--~ 	log = log,
	log = quiet,
	--
	----------------------------
	-- storage functions
	

	sget = function(server, bname)
		return he.fget(server.store_path .. bname) 
	end, 

	sput = function(server, bname, blob)
		return he.fput(server.store_path .. bname, blob)
	end,

	sdel = function(server, bname)
		return os.remove(server.store_path .. bname)
	end,
	
	----------------------------
	-- server operation handlers
	-- handler sig: function(server, id, blob) return rcode, rblob
	--
	[henb.NOP] = function(server, id, blob) 
		return henb.OK, "" 
	end,

	[henb.EXIT] = function(server, id, blob) 
		server.log("exit requested")
		server.exit_server = true
		return henb.OK, ""
	end,

	[henb.GET] = function(server, id, blob)
		local rblob = server.sget(server, id)
		if rblob then
			return henb.OK, rblob
		else
			return henb.NOTFOUND, ""
		end
	end,

	[henb.PUT] = function(server, id, blob)	
		server.sput(server, id, blob)
		return henb.OK, ""
	end,

	[henb.CHK] = function(server, id, blob)	
		local b = server.sget(server, id)
		if not b then return henb.NOTFOUND, "" end
		return henb.OK, spack("<I4", #b)
	end,

	[henb.DEL] = function(server, id, blob)	
		local r, msg = server.sdel(server, id)
		if not r then 
			server.log("del error:", msg)
			return henb.DELERR, "" end
		return henb.OK, ""
	end,
	----------------------------

} --server

function henb.serve(server)
	server = server or henb.default_server
	local sso, cso -- server socket, client socket
	local msg, code, idln, id, bln, blob, rcode, rblob
	local handler
	local sso = assert(hesock.bind(server.host, server.port))
	server.log(strf("phs: bound to %s %d", hesock.getserverinfo(sso)))
	while true do
		if server.exit_server then
			cso:close()
			sso:close()
			return 
		end
		cso, msg = sso:accept()
		if not cso then log("accept error", msg); goto continue end
		local cso_ip, cso_port = hesock.getclientinfo(cso)
		server.log("serve client", cso_ip, cso_port)
		code, id, blob = receive(cso)
		if not code then server.log("no code"); goto close end
		handler = server[code]
		if not handler then
			send(cso, henb.UNKNOWN, "") -- unknown code
		else
--~ server.log("request code, id, bln: ", code, he.repr(id), #blob)
			rcode, rblob = handler(server, id, blob)
--~ server.log("response rcode, rblob: ", rcode, he.repr(rblob))
			send(cso, rcode, "", rblob)
		end
		::close::
		cso:close()
		::continue::
	end--while
end--serve()
------------------------------------------------------------------------

-- allows to run a test server with "slua henb.lua test"
-- it doesn't run when henb is required.
-- added arg[1] to allow quick syntax check within scite/F5 
-- without launching server!
-- NO! must be run in cur dir => doesnt work with require-based test!!
--~ if arg[0] == "henb.lua" and arg[1] == "test" then serve() end

------------------------------------------------------------------------
return henb



