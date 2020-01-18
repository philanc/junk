#!/ut/bin/slua

--[[   rxc.lua:  rx cli command

 
 ]]
 
local he = require "he"
local rx = require "rx"
local getargs = require "args"

local server = require "rxconf"

local ppp=print
local list, strf, printf, repr = he.list, string.format, he.printf, he.repr

local cmdt = {}

function cmdt.help()
	local htext = strf([[
Usage: %s command [options]

Common options:

Commands:
	help, h   display this text
	log       return last log lines
	ping      return server time and time difference with server
	ps        run "ps -f"
	rest      restart the server
	sh 'cmd'  run shell command 'cmd  2>&1'        
	shut      shutdown the server
	]], arg[0])
	print(htext)
end--help()

function cmdt.log(at)
	local l, m = rx.sh(server, 'tail -n 15 rxd.log ')
	print(l or m)
end--log

function cmdt.ping(at)
	local rt, m = rx.lua(server, [[
		local reqt = ... 
		local he = require "he"
		rt = {ok=true}
		local ctime = string.unpack("<I4", reqt.nonce)
		local stime = os.time()	
		rt.td = ctime - stime
		rt.st = he.isodate19()
		return rt
	]], "ping server")
	if not rt then return print(m) end
	local st, td = tostring(rt.st), tostring(rt.td) 
	print(strf("client time: %s", he.isodate19()))
	print(strf("server time: %s   ctime-stime: %s\n", st, td))
end--ping

function cmdt.ps(at)
	local l, m = rx.sh(server, 'ps -f ')
	print(l or m)
end--ps

function cmdt.sh(at)
	local c = at[2]
	c = c .. " 2>&1"
	print("rxc sh:",repr(c))
	local l, m = rx.sh(server, c)
	print(l or m)	
end

function cmdt.shut(at)
	local desc = "shutdown requested"
	print("***  " .. he.isodate(), desc)
	rx.lua(server, "return {ok=true, exitcode=1}", desc)
end

function cmdt.rest(at)
	local desc = "restart requested"
	print("***  " .. he.isodate(), desc)
	rx.lua(server, "return {ok=true, exitcode=0}", desc)
end


-- aliases
cmdt.h = cmdt.help




local function rxcmd()
	local at = getargs()
	local cmd = at[1]
	if not cmd then return cmdt.help() end
	local cmdfn = cmdt[cmd]
	if cmdfn then cmdfn(at)
	else printf("rxc: unknown command '%s'\n", cmd)
	end--if
end--rxcmd
	

rxcmd()


 