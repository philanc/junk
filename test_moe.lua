
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
x=1200000
p = ("a"):rep(x)
he.fput("moedat.p", p)
local fhi = io.open("moedat.p")
local fho =  io.open("moedat.c", "w")
y, msg = moe.fhencrypt(k, fhi, fho)
--~ print("moedat.c", y)
assert(y == x + (moe.noncelen + moe.maclen) * 2)
fhi:close()
fho:close()
--
local fhi = io.open("moedat.c")
local fho =  io.open("moedat.p2", "w")
z, msg = moe.fhdecrypt(k, fhi, fho)
assert(z and (z == x), msg)
--~ print("moedat.p2", x, msg)
fhi:close()
fho:close()
assert(he.fget("moedat.p2") == he.fget("moedat.p"))
os.remove("moedat.p")
os.remove("moedat.p2")
os.remove("moedat.c")
print("test_moe:  ok")
