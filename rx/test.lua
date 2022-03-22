
-- launch:   slua test.lua


print("launch server", os.execute("(./rxs-local >test.log &) ; sleep 1"))

local rxc = require"rxc"

local server = assert(rxc.loadconf("local"))

print("refresh key", rxc.refreshkey(server))

local rcode, rdata = rxc.request(server, "date")
print(rcode, rdata)

local rcode, rdata = rxc.request(server, "MUSTEXIT")
print(rcode, rdata)


