-- rx client
local rxc = require"rxc"
local util = require "util"
local lm = require 'luamonocypher'

local r, err

-- init server 

local server = {
	name = "local",
	addr = "127.0.0.1",
	port = 4096,
}
server.key = util.fget(server.name .. ".k") -- maybe nil
server.msk = lm.b64decode("vlAp8AfDryNqW1qkJbo1WeOnqxLHckxQ89YKKmK9Dws")

r, err = rxc.clientinit(server)
if not r then 
	print("clientinit:", err)
end

rxc.refreshkey(server)

--~ util.px(server.mpk)
--~ os.exit(33)

local rcode, rdata


print(rxc.request(server, "	pwd	"))
--~ print(rxc.request(server, "	date	"))
print(rxc.request(server, "MUSTEXIT"))

