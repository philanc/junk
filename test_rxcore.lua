

local rxcore = require "rxcore"


------------------------------------------------------------------------
-- imports and local definitions

--~ local he = require 'he'
he = require 'he'  -- make he global for request chunks

local list, strf, printf, repr = he.list, string.format, he.printf, he.repr
local rep, spack, sunpack = string.rep, string.pack, string.unpack

local function px(s, msg) 
	print("--", msg or "")
	print(he.stohex(s, 16, " ")) 
end

local function repr(x)
	return strf("%q", x) 
end

local function pr(x) print(repr(x)) end

------------------------------------------------------------------------

local k = rep('k', 32)
--~ local k = rep('k', 16)

local rid, rid1, rid2, rid3, len, code, arg, data, ctr, rnd, time
local eh, ed, eh2, ed2, h2, d2
local n2, x, y, z, t, r

rid1 = rxcore.new_reqid()
time = sunpack("<I4", rid1)
assert(math.abs(time - os.time()) <= 1)
assert(#rid1 == 15)

rid2, n2, eh, ed = rxcore.wrap_req(k, 111, 222)
assert(rid2 ~= rid1)
assert(#eh == rxcore.HDRLEN and #n2 == rxcore.NONCELEN)
assert(n2:sub(1, rxcore.NONCELEN - 1) == rid2)
assert(#eh == 32)
assert(ed == nil)

data = "hello"
rid2, n2, eh, ed = rxcore.wrap_req(k, 111, 222, data)
assert(rid2 ~= rid1)
assert(#eh == rxcore.HDRLEN and #n2 == rxcore.NONCELEN)
assert(#ed == #data + rxcore.MACLEN)

t, r, x = sunpack("<I4c11I1", n2)
assert(math.abs(time - os.time()) <= 2)
assert(x == 0)

--~ pr(rid2)
--~ pr(rid3)
rid3, ctr, len, code, arg = rxcore.unwrap_hdr(k, rid2, 0, eh)

--~ px(rid3)
--~ print(ctr)
--~ px(rid2)
assert(rid3 == rid2)
assert(ctr == 0)
assert(len == #data)
assert(code == 111)
assert(arg == 222)
local d2 = rxcore.unwrap_data(k, rid2, 1, ed)
assert(d2 == data)


