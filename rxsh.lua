
------------------------------------------------------------------------
-- imports and local definitions

he = require 'he'
local hefs = require 'hefs'
local hezen = require 'hezen'
local hepack = require 'hepack'
local hesock = require 'hesock'

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local spack, sunpack = string.pack, string.unpack
local pp, ppl, ppt = he.pp, he.ppl, he.ppt

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end

------------------------------------------------------------------------
-- rxc

local rxc = require 'rxc'

rxd = assert(rxc.load_rxd_config({config_filename = "rxd.conf.lua"}))


------------------------------------------------------------------------
-- utilities

function rget(fpath)
	local s, msg = rxc.file_download(rxd, fpath)
	return s, msg
end

function download(fpath)
	local s, msg = rxc.file_download(rxd, fpath)
	local fname = he.basename(fpath)
	he.fput(fname, s)
end

function disp(fpath)
	local s, msg = rxc.file_download(rxd, fpath)
	if not s then print("Download error:", msg) end
	print(s)
end

function lua(cmd)
	local r, msg = rxc.lua(rxd, cmd)
	if not r then 
		print("Lua error:", msg)
	end
	print(r)
end	

function shell(cmd, sin)
	cmd = cmd .. " 2>&1 "
	local r, exitcode = rxc.shell(rxd, cmd, sin)
	if not r then
		printf("ERROR -- server or communication error: " .. exitcode)
	elseif math.type(exitcode) == "integer" and exitcode > 0 then
		printf("EXIT %d\n%s---", exitcode, r)
	else
		print(r)
	end
end

------------------------------------------------------------------------
-- examples


--~ lua[[ return string.format("%s - client time is %d sec lower.",
--~ 	he.strip(he.shell"date"), os.time()-req.reqtime) ]]

--~ shell[[ touch /dev/shm/zzl1 ]]
--~ shell[[ ls -la /dev/shm ]]

-- display the log file
--~ print(rget"/home/l1/rxd/rxd.log")

-- display last lines of the log file
--~ shell[[ tail /home/l1/rxd/rxd.log ]]
--~ shell[[ tail rxd.log ]]

-- empty the rxd log file
--~ lua[[ he.fput("/home/l1/rxd/rxd.log", "") ]]

--update server
--~ print(rxc.file_upload(rxd, "./rxd.lua", he.fget("./rxd.lua")))
--~ print(rxc.lua(rxd, "rxd.exitcode = 0"))

c1 = strf([[ cd /var/log
grep "DPT=3761" syslog* \
	| grep -v "%s"  \
	| sed 's/DST=.*$//' \
	| sed 's/atlanta.*SRC=/\t/' \
	| awk '{print($4); }' \
	| sort -n  \
	2>&1
	]], rxd.client_addr)
--~ shell(c1)

--~ shell[[ ls -l /var/log ]]

--~ shell[[ ps -opid,pgid,command ]]

--~ shell[[ tail rxd.log ]]
shell[[ date ]]

--~ status, resp = rxc.request(rxd, "", "")
--~ print(status, repr(resp))
