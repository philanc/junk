
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

