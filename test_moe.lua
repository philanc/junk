
-- test_moe.lua 

------------------------------------------------------------------------

local moe = require "moe"

require"hei"
--~ he.pp(moe)

local k = ('k'):rep(32)
local p, p2, c, msg, clen, x, y, z
p = "hello"
c = moe.encrypt(k, p, true)
--~ print("#c, c:", #c, c)
assert(moe.decrypt(k, c, true) == p)
--
-- file names
local fbase = "/tmp/" .. os.getenv("USER") .. "-moetest"
local fnp = fbase .. ".p"
local fnc = fbase .. ".c"
local fnp2 = fbase .. ".p2"
--
x=1200000
p = ("a"):rep(x)
he.fput(fnp, p)
local fhi = io.open(fnp)
local fho =  io.open(fnc, "w")
y, msg = moe.fhencrypt(k, fhi, fho)
assert(y == x + (moe.noncelen + moe.maclen) * 2)
fhi:close()
fho:close()
local fhi = io.open(fnc)
local fho =  io.open(fnp2, "w")
z, msg = moe.fhdecrypt(k, fhi, fho)
assert(z and (z == x), msg)
--~ print("moedat.p2", x, msg)
fhi:close()
fho:close()
assert(he.fget(fnp2) == he.fget(fnp))
os.remove(fnp)
os.remove(fnp2)
os.remove(fnc)
print("test_moe:  ok")
