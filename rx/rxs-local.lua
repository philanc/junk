-- #####################################################################
-- module:  util

package.preload["util"] = function()
-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
-- simple utility functions

local spack, sunpack, strf = string.pack, string.unpack, string.format

util = {}

function util.pf(...) print(strf(...)) end

function util.px(s, msg) -- hex dump the string s
	if msg then print(msg) end
	for i = 1, #s-1 do
		io.write(strf("%02x", s:byte(i)))
		if i%4==0 then io.write(' ') end
		if i%8==0 then io.write(' ') end
		if i%16==0 then io.write('') end
		if i%32==0 then io.write('\n') end
	end
	io.write(strf("%02x\n", s:byte(#s)))
end

function util.repr(x) return string.format('%q', x) end

function util.rpad(s, w, ch) 
	-- pad s to the right to width w with char ch
	return (#s < w) and s .. ch:rep(w - #s) or s
end

function util.lstrip(s)
	-- remove whitespace at beginning of string s
	s = string.gsub(s, '^%s+', '')
	return s  -- return only 1st value returned by gsub
end

function util.rstrip(s) 
	-- remove whitespace at end of string s
	s = string.gsub(s, '%s+$', '')
	return s  -- return only 1st value returned by gsub
end

function util.strip(s) 
	-- remove whitespace at both ends of string s
	return util.lstrip(util.rstrip(s)) 
end

-- hex representation of binary strings

function util.stohex(s, ln, sep)
	-- stohex(s [, ln [, sep]])
	-- return the hex encoding of string s
	-- ln: (optional) a newline is inserted after 'ln' bytes 
	--	ie. after 2*ln hex digits. Defaults to no newlines.
	-- sep: (optional) separator between bytes in the encoded string
	--	defaults to nothing (if ln is nil, sep is ignored)
	-- example: 
	--	stohex('abcdef', 4, ":") => '61:62:63:64\n65:66'
	--	stohex('abcdef') => '616263646566'
	--
	local strf, byte = string.format, string.byte
	if #s == 0 then return "" end
	if not ln then -- no newline, no separator: do it the fast way!
		return (s:gsub('.', 
			function(c) return strf('%02x', byte(c)) end
			))
	end
	sep = sep or "" -- optional separator between each byte
	local t = {}
	for i = 1, #s - 1 do
		t[#t + 1] = strf("%02x%s", s:byte(i),
				(i % ln == 0) and '\n' or sep) 
	end
	-- last byte, without any sep appended
	t[#t + 1] = strf("%02x", s:byte(#s))
	return table.concat(t)	
end --stohex()

function util.hextos(hs, unsafe)
	-- decode an hex encoded string. return the decoded string
	-- if optional parameter unsafe is defined, assume the hex
	-- string is well formed (no checks, no whitespace removal).
	-- Default is to remove white spaces (incl newlines)
	-- and check that the hex string is well formed
	local tonumber, char = tonumber, string.char
	if not unsafe then
		hs = string.gsub(hs, "%s+", "") -- remove whitespaces
		if string.find(hs, '[^0-9A-Za-z]') or #hs % 2 ~= 0 then
			error("invalid hex string")
		end
	end
	return (hs:gsub(	'(%x%x)', 
		function(c) return char(tonumber(c, 16)) end
		))
end -- hextos

function util.errm(err, txt)
	-- errm(17, "open") => "open error: 17"
	-- errm(17)         => "error: 17"
	-- errm(0, "xyz")   => nil
	if err == 0 then return end
	local s = "error: " .. tostring(err)
	return txt and (txt .. " " .. s) or s
end
	
function util.fget(fname)
	-- return content of file 'fname' or nil, msg in case of error
	local f, msg, s
	f, msg = io.open(fname, 'rb')
	if not f then return nil, msg end
	s, msg = f:read("*a")
	f:close()
	if not s then return nil, msg end
	return s
end

function util.fput(fname, content)
	-- write 'content' to file 'fname'
	-- return true in case of success, or nil, msg in case of error
	local f, msg, r
	f, msg = io.open(fname, 'wb')
	if not f then return nil, msg end
	r, msg = f:write(content)
	f:flush(); f:close()
	if not r then return nil, msg else return true end
end

function util.isots(t, utcflag)
	-- return ISO date-time (local time) as a string that can be 
	-- used as a timestamp, an identifier or a filename 
	-- eg. 20090709_122122
	local fmt = "%Y%m%d_%H%M%S"
	if utcflag then fmt = "!" .. fmt end
	return os.date(fmt, t)
end





------------------------------------------------------------------------
return util

end --module: util



-- #####################################################################
-- module:  ssock

package.preload["ssock"] = function()

-- ssock  - stream sockets
-- lualinux-based ip4 stream/tcp socket interface

local lualinux = require "lualinux"
local util = require "util"

local spack, sunpack, strf = string.pack, string.unpack, string.format

------------------------------------------------------------------------

local sock = {
	AF_UNIX = 1, 
	AF_INET = 2,
	AF_INET6 = 10,
	DONTWAIT = 0x40,  -- non-blocking flag for send/recv functions
	BUFSIZE = 4096,   -- lualinux.read buffer size
	SOCK_STREAM = 0x01,
	SOCK_DGRAM = 0x02,
	SOCK_CLOEXEC = 0x80000,
	SOCK_NONBLOCK = 0x0800,
	SOL_SOCKET = 1,
	SO_REUSEADDR = 2,
	-- std errors
	EAGAIN = 11, -- same as EWOULDBLOCK (on any recent unix)
	EBUSY = 16,
	-- local errors (outside of the range of errno numbers)
	EOF = 0x10000,
	TIMEOUT = 0x10001,
}-- sock


function sock.sbind(sa, nonblocking, backlog)
	-- create a stream socket object, bind it to sockaddr sa,
	-- and start listening.
	-- default options: CLOEXEC, blocking, REUSEADDR
	-- sa is a sockaddr struct encoded as a string (see sockaddr())
	-- if nonblocking is true, the socket is non-blocking
	-- backlog is the backlog size for listen(). it defaults to 32.
	-- return the socket object, or nil, eno, msg
	local so = { 
		nonblocking = nonblocking, 
		backlog = backlog or 32, 
		stream = true,
		sa = sa,
	}
	local family  = sock.sa4_split(sa)
	local sotype = sock.SOCK_STREAM | sock.SOCK_CLOEXEC
	if nonblocking then sotype = sotype | sock.SOCK_NONBLOCK end
	local fd, eno = lualinux.socket(family, sotype, 0)
	if not fd then return nil, eno, "socket" end
	so.fd = fd
	local r
	r, eno = lualinux.setsockopt(so.fd, 
			sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
	if not r then return nil, eno, "setsockopt" end
	r, eno = lualinux.bind(so.fd, sa)
	if not r then return nil, eno, "bind" end
	r, eno = lualinux.listen(so.fd, so.backlog)
	if not r then return nil, eno, "listen" end
	return so
end

function sock.sconnect(sa, nonblocking)
	-- create a stream socket object, and connect it to server 
	-- address sa (a sockaddr string)
	-- if nonblocking is true, the socket is non-blocking
	-- default options: CLOEXEC, blocking
	-- return the socket object, or nil, eno, info
	local so = { 
		nonblocking = nonblocking, 
		stream = true,
		sa = sa
	}
	local family, port, ip = sock.sa4_split(sa)
	local sotype = sock.SOCK_STREAM | sock.SOCK_CLOEXEC
	if nonblocking then sotype = sotype | sock.SOCK_NONBLOCK end
	local fd, eno = lualinux.socket(family, sotype, 0)
	if not fd then return nil, eno, "socket" end
	so.fd = fd
	local r
	r, eno = lualinux.connect(fd, sa)
	if not r then return nil, eno, "connect" end
	return so
end

function sock.close(so) 
	return lualinux.close(so.fd)
end

function sock.settimeout(so, ms)
	local r, eno = lualinux.setsocktimeout(so.fd, ms)
	if not r then return nil, eno, "setsocktimeout" end
	return so
end

function sock.accept(so, nonblocking)
	-- accept a connection on server socket object so
	-- return cso, a socket object for the accepted client.
	local flags = sock.SOCK_CLOEXEC
	if nonblocking then flags = flags | sock.SOCK_NONBLOCK end
	local cfd, csa = lualinux.accept(so.fd, flags)
	if not cfd then return nil, csa end -- here csa is the errno.
	local cso = { 
		fd = cfd,
		sa = csa,
		nonblocking = nonblocking,
		stream = true,
	}
	return cso
end

-- sock readbytes and readline functions: at the moment not very efficient
-- (concat read string with buffer at each read operation - should
-- replace the buf string with a table) -- to be optimized later! 

function sock.readline(so)
	-- buffered read. read a line
	-- return line (without eol) or nil, errno
	local eno -- errno
	so.buf = so.buf or "" -- read buffer
--~ 	so.bi = so.bi or 1 -- buffer index
	while true do
		local i, j = so.buf:find("\r?\n")
		if i then -- NL found. return the line
			local l = so.buf:sub(1, i-1)
			so.buf = so.buf:sub(j + 1)
			return l
		else -- NL not found. read more bytes into buf
			local b, eno = lualinux.read(so.fd)
			if not b then
				return nil, eno
			end
--~ 				print("READ", b and #b)
			if #b == 0 then return nil, sock.EOF end
			so.buf = so.buf .. b
		end--if
	end--while reading a line
end

function sock.readbytes(so, n)
	-- buffered read: read n bytes
	-- return read bytes as a string, or nil, errmsg
	so.buf = so.buf or "" -- read buffer
	local nbs -- "n bytes string" -- expected result
	local eno -- errno
	while true do
		if n <= #so.buf then -- enough bytes in buf
			nbs = so.buf:sub(1, n)
			-- keep not needed bytes in buf
			so.buf = so.buf:sub(n+1)
			return nbs
		else -- not enough, read more
			local b, eno = lualinux.read(so.fd)
			if not b then
				return nil, eno
			end
			if #b == 0 then
				--EOF, not enough bytes
				-- return what we have
				nbs = buf
				so.buf = ""
				return nbs
			end
			so.buf = so.buf .. b
		end
	end--while reading n bytes
end

sock.read = sock.readbytes  -- define a common alias

function sock.readbuf(so)
	-- attempt to read sock.BUFSIZE bytes from the socket
	-- (ignore the socket object buffer - raw access to 
	-- the read() syscall)
	return lualinux.read(so.fd)
end

function sock.write(so, str, idx, cnt)
	-- write cnt bytes from string str at index idx fo socket object
	-- return number of bytes actually written or nil, errno
	-- idx, cnt default to 1, #str
	return lualinux.write(so.fd, str, idx, cnt)
end

function sock.writeall(so, str)
	-- write str. Repeat calling write() until all bytes in str are
	-- written. return number of bytes actually written (should be #str)
	-- or nil, errno
	local idx, cnt = 1, #str
	local r, eno
	while true do
		r, eno = lualinux.write(so.fd, str, idx, cnt)
		if not r then return nil, eno end
		if r < cnt then
			idx = idx + r
			cnt = cnt - r
		else
			break
		end
	end--while
	return #str
end


function sock.flush(so)
	return lualinux.fsync(so.fd)
end

------------------------------------------------------------------------
-- sockaddr utilities


function sock.sa(addr, port)
	-- turn an address (as a string) and a port number
	-- into a sockaddr struct, returned as a string
	-- addr is either an ip v4 numeric address (eg. "1.23.34.56")
	-- or a unix socket pathname (eg. "/tmp/xyz_socket")
	-- (in the case of a Unix socket, the pathname must include a '/')
	local sa
	if addr:find("/") then --assume this is an AF_UNIX socket
		if #addr > 107 then return nil, "pathname too long" end
		return spack("=Hz", sock.AF_UNIX, addr)
	end
	-- ipv6 addr not supported yet
	-- if addr:find(":") then --assume this is an AF_INET6 socket
	-- end

	-- here, assume this is an ipv4 address
	local ippat = "(%d+)%.(%d+)%.(%d+)%.(%d+)"
	local ip1, ip2, ip3, ip4 = addr:match(ippat)
	ip1 = tonumber(ip1); ip2 = tonumber(ip2);
	ip3 = tonumber(ip3); ip4 = tonumber(ip4);
	local function bad(b) return b < 0 or b > 255 end
	if not ip1 or bad(ip1) or bad(ip2) or bad(ip3) or bad(ip4) then
		return nil, "invalid address"
	end
	if (not math.type(port) == "integer")
		or port <=0 or port > 65535 then
		return nil, "not a valid port"
	end
	return spack("<H>HBBBBI8", sock.AF_INET, port, ip1, ip2, ip3, ip4, 0)
end

function sock.sa4_split(sa)
	-- extract components from an ip4 sockaddr string
	-- return family, port, address as integers
	local family, port, ip = sunpack("<H>HI", sa)
	if family == sock.AF_INET then
		return family, port, ip
	else
		return nil, "sockaddr family not supported: " .. family
	end
end

function sock.ip4tos(ip) 
	-- turns an ip4 address (as an integer) into the common
	-- string representation (eg. "192.168.0.1")
	local s = strf("%d.%d.%d.%d", 
			(ip >> 24) & 0xff, 
			(ip >> 16) & 0xff, 
			(ip >> 8 ) & 0xff, 
			(ip      ) & 0xff )
	return s
end


------------------------------------------------------------------------

--~ print(sock.ip4tos(0xadb0828a))

return sock


end --module: ssock



-- #####################################################################
-- module:  rxs

package.preload["rxs"] = function()
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



end --module: rxs



-- #####################################################################
-- main:  rxs-local.lua

local rxs = require"rxs"
local util = require "util"
local lm = require 'luamonocypher'
local mpk = "2cca91f6a4e8e198687042dc0ebc1ad29e18f21c77152b9590ae5f4af9474836"
mpk = assert(util.hextos(mpk))
local server = { mpk = mpk,  port = 4096,  }
assert(rxs.serverinit(server))
rxs.runserver(server)

