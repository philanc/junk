
-- test_moe.lua 

------------------------------------------------------------------------

local moe = require "moe"

require"hei" ; he.pp(moe)

local k = ('k'):rep(32)
local p, p2, c, msg
p = "hello"
c = moe.encrypt(k, p, true)
--~ print("#c, c:", #c, c)
assert(moe.decrypt(k, c, true) == p)

x=1024*1
p = ("a"):rep(x)
a=os.clock()
c = moe.encrypt(k, p)
b=os.clock()
print("clock", a, b, (b-a)*1000)	
--~ print(lz)
--~ print(os.clock())
--~ for i = 1,1000000 do x = lz.randombytes(16) end
--~ print(os.clock())
--~ print(x)

print("test_moe:  ok")
