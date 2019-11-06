
-- test_moe.lua 

------------------------------------------------------------------------

local moe = require "moe"

print("crypto and nonce generation: ", moe.use())

local he = require"he"
--~ he.pp(moe)

local k = ('k'):rep(32)
local p, p2, c, msg, clen, x, y, z
--
-- string en/decryption
p = "hello"
c = moe.encrypt(k, p, true)
--~ print("#c, c:", #c, c)

-- switch to plc-based crypto for decryption
print(moe.use("plc"))
print("crypto and nonce generation: ", moe.use())
assert(moe.decrypt(k, c, true) == p)
--
-- file names
local fbase = "/tmp/" .. os.getenv("USER") .. "-moetest"
local fnp = fbase .. ".p"
local fnc = fbase .. ".c"
local fnp2 = fbase .. ".p2"
local fnp3 = fbase .. ".p3"
--
-- test file handle en/decrypt
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
--
-- test file en/decrypt
assert(moe.fileencrypt(k, fnp, fnc))
assert(moe.filedecrypt(k, fnc, fnp3))
assert(he.fget(fnp3) == he.fget(fnp))
--
-- cleanup test files
os.remove(fnp)
os.remove(fnp2)
os.remove(fnp3)
os.remove(fnc)
print("test_moe:  ok")
