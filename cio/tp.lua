



he = require "he" -- at https://github.com/philanc/he

l5 = require "l5"

util = require "l5.util"
tty = require "l5.tty"
fs = require "l5.fs"

local spack, sunpack = string.pack, string.unpack
local insert, concat = table.insert, table.concat

local errm, rpad, repr = util.errm, util.rpad, util.repr
local pf, px = util.pf, util.px


------------------------------------------------------------------------
-- test popen2

local POLLIN, POLLOUT = 1, 4
local POLLNVAL, POLLUP, POLLERR = 32, 16, 8

local function pollinout(fdin, fdout, timeout)
	-- timeout is optional
	local pfl = {
		(fdin << 32 | POLLIN << 16), 
		(fdout << 32 | POLLOUT << 16), 
	}
	local r, err, rin, rout
	r, err = l5.poll(pfl, timeout)
	if not r then return nil, err end
	return r, pfl[1] & 0xffff, pfl[2] & 0xffff
end

local function popen2raw(exepath, in_str, argl, envl)
	envl = envl or l5.environ()
	argl = argl or {}
	local r, err
	local rfd0, rfd1 = l5.pipe2() -- child reads from this
	assert(rfd0, rfd1)
	local wfd0, wfd1 = l5.pipe2() -- child writes to this
	assert(wfd0, wfd1)
	local pid
	pid, err = l5.fork()
	if not pid then return nil, "fork error " .. err end
	if pid == 0 then -- child
		local r, err
		l5.close(rfd1) -- close unused ends
		l5.close(wfd0) -- id.
		assert(l5.dup2(rfd0, 0))
		l5.close(rfd0)
		assert(l5.dup2(wfd1, 1))
		l5.close(wfd1)
--~ 		table.insert(argl, 1, exepath)
		r, err = l5.execve(exepath, argl, envl)
		print("CHILD", r, err)
		os.exit(99)
	end
	-- parent
	l5.close(rfd0)
	l5.close(wfd1)
	print("child pid:", pid, "#s", #in_str)
	
	-- check if child has already returned
	-- give the child some time to start ...arghhh smelly and not reliable
	l5.msleep(100) 
	local WNOHANG = 1 -- waitpid doesnt block
	wpid = pid
--~ 	local wpid, status = l5.waitpid(pid, WNOHANG)
--~ 	pf("wpid %d   status 0x%x  exit=%d  signal=%d   coredump=%d",
--~ 		wpid, status, 
--~ 		(status & 0xff00) >> 8, 
--~ 		status & 0x7f, 
--~ 		status & 0x80)
--~ 	if (status >> 8) & 0xff == 99 then
--~ 		-- child exec error. close wfd0, rfd1
--~ 		l5.close(wfd0)
--~ 		l5.close(rfd1)
--~ 		return nil, "exec errorzz"
--~ 	end
	-- write to rfd1,   read from wfd0
	local rdone, wdone
	if wpid then wdone = true end -- child already exited. no need to write
	local r, rr, wr, err, rin, rout
	local pollerr
	local cnt
	local rtot = 0
	local si = 1 -- write index
	local POLLIN, POLLOUT = 1, 4
	local POLLNVAL, POLLUP, POLLERR = 32, 16, 8
	local rt = {} -- read table
	local fdin, fdout = wfd0, rfd1
	while true do
		if wdone then -- ignore fdout
			fdout = -1 
		end 
		r, rin, rout = pollinout(fdin, fdout)
--~ 			print("pollinout", r, rin, rout)
		if not r then
			err = rin
			print("pollinout error", err)
			os.exit(99)
		end
		if r == 0 then --timeout
			goto continue
		end
		
		if rdone and wdone then break end
		
		if not rdone then -- read
			if rin == 0 then
				-- nothing to read
			elseif rin == POLLNVAL then 
				rdone = true 
			elseif rin & POLLIN == POLLIN then --can read
				rr, err = l5.read(wfd0)
				if not rr then
					print("read error", err)
					os.exit(99)
				elseif #rr > 0 then
					rt[#rt+1] = rr
					rtot = rtot + #rr
--~ 						print("read n bytes, total", #rr, rtot)
				else 
					print("read empty string => EOF(?)")
					rdone = true
				end
			elseif rin & POLLUP == POLLUP then 
				rdone = true
			else
				print("unknown rin value", rin)
			end --if rin
		end --if not rdone
		
		if not wdone then -- write
			if rout == 0 then
				-- cannot write
			elseif rout == POLLNVAL then 
				wdone = true 
			elseif rout == POLLERR then 
				wdone = true 
				l5.close(rfd1)
				pollerr = "cannot write to child process"
			elseif rout & POLLOUT == POLLOUT then --can write
				cnt = #in_str - si + 1
				if cnt > 4096 then cnt = 4096 end;
				wr, err = l5.write(rfd1, in_str, si, cnt)
				if not wr then
					print("write error", err)
					os.exit(99)
				elseif wr > 0 then
					si = si + wr
--~ 						print("write: wr, si, #s", wr, si, #s)
					if si >= #in_str then 
						wdone = true 
						l5.close(rfd1)
					end
				else 
					print("wrote empty string?", r)
				end
			else
				print("unknown rout value", rout)
			end --if rout
		end --if not wdone
		
		::continue::
--~ 			print("pollinout", r, rin, rout, 
--~ 				"read", rr and #rr,
--~ 				"write", wr
--~ 				)
		rr = ""; wr = 0
	end--while
	
	r = table.concat(rt, "")
	print("#r", #r)
	wpid, status = l5.waitpid(pid)
	pf("pid: %s   status: %x  exit: %d", wpid, status, (status & 0xff00)>>8)
	if pollerr then return nil, pollerr end
	return r
end --popen2raw()

local function popen2(cmd, in_str, envl)
	envl = envl or l5.environ()
	local argl = {"bash", "-c", cmd}
	return popen2raw("/bin/bash", in_str, argl, envl)
end
	

function test_popen2raw()
	local s = assert(he.fget"z856k")
	local pname = "/bin/gzip"
	local r, err = popen2raw(pname, s)
	if not r then 
		print("test_popen2 failed:", err)
	else
		he.fput('zzaa.gz', r)
		print("test_popen2raw: ok.")
	end
end

function test_popen2()
	local s = assert(he.fget"z856k")
--~ 	local cmd = "gzip -xqx 2>&1"
	local cmd = "pwd -qwe 2>&1"
	local r, err = popen2(cmd, s, l5.environ())
	print("POPEN2", r, err)
	if not r then 
		print("test_popen2 failed:", err)
	else
		he.fput('zzaa.gz', r)
		print("test_popen2: ok.")
	end
end


------------------------------------------------------------------------


--~ test_popen2raw()
test_popen2()

------------------------------------------------------------------------
--[[  

TEMP NOTES  


]]


	

