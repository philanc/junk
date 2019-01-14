
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

-- server info
rxd = { 
	log = print,
	config_filename = "rxd.conf.lua",
}
assert(rxc.load_rxd_config())


-- prepare req
req = { rxs = rxd }

------------------------------------------------------------------------
-- utilities

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
	local rcode, rpb = rxc.shell(rxd, cmd, sin)
	if not rcode then
		printf("ERROR -- server or communication error")
	elseif rcode > 0 then
		printf("ERROR %d\n%s---", rcode, rpb)
	else
		print(rpb)
	end
end

------------------------------------------------------------------------
-- examples


lua[[ return string.format("%s - client time is %d sec lower.",
	he.strip(he.shell"date"), os.time()-req.reqtime) ]]

shell[[ ps -opid,pgid,command ]]




-- done


