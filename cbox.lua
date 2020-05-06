-- Copyright (c) 2020  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[ 

cbox encryption/decryption

?? what random function ??  

]]
------------------------------------------------------------------------

local nacl = require "plc.box"
local base64 = require "plc.base64"

local ben, bde = base64.encode, base64.decode 

local strf = string.format
local byte, char = string.byte, string.char
local spack, sunpack = string.pack, string.unpack
local app, concat = table.insert, table.concat

------------------------------------------------------------------------

local cbox = {}

function cbox.randombytes(n)
	-- return n random bytes as a string
	local rdev = io.open("/dev/urandom", "r")
	assert(rdev, "cannot open /dev/urandom")
	local rs = rdev:read(n)
	assert(rs and #rs == n, "cannot read /dev/urandom")
	rdev:close()
	return rs
end

function cbox.encr(kb, pt)
	-- encrypt pt with key kb
	-- kb is a 32-byte key base64-encoded
	-- return the encrypted text, base64-encoded
	local nonce = cbox.randombytes(24)
	local k = bde(kb)
	local et = nacl.secretbox(pt, nonce, k)
	et = nonce .. et
	return ben(et)
end --cbox.encr

function cbox.decr(kb, et)
	et = bde(et)
	local nonce = et:sub(1, 24)
	local et = et:sub(25)
	local k = bde(kb)
	local pt, m = nacl.secretbox_open(et, nonce, k)
	return pt, m
end --cbox.decr

function cbox.pken(skb, pkb, pt)
	local sk, pk = bde(skb), bde(pkb)
	local nonce = cbox.randombytes(24)
	local et = nacl.box(pt, nonce, pk, sk)
	return ben(nonce .. et)
end

function cbox.pkde(skb, pkb, et)
	et = bde(et)
	local nonce = et:sub(1, 24)
	local et = et:sub(25)
	local sk, pk = bde(skb), bde(pkb)
	local pt, m = nacl.box_open(et, nonce, pk, sk)
	if not pt then return nil, m end
	return pt
end

function cbox.apken(pkb, pt)
	-- anonymous pk encryption
	-- (sender encrypts with an "anonymous", random keypair
	local ask = cbox.randombytes(32)
	local apk = nacl.public_key(ask)
	local pk = bde(pkb)
	local nonce = apk:sub(1, 24)
	local et = nacl.box(pt, nonce, pk, ask)
	return ben(apk .. et)
end

function cbox.apkde(skb, et)
	et = bde(et)
	local apk = et:sub(1, 32)
	local nonce = apk:sub(1, 24)
	local et = et:sub(33)
	local sk = bde(skb)
	local pt, m = nacl.box_open(et, nonce, apk, sk)
	if not pt then return nil, m end
	return pt
end

function cbox.test()
	local kb, skb, pkb = 
		"1/ZIkMm6CiwW1gNL9X+1fYtaMC5/8+ws18c+Gs/FhFU=",
		"899PBLBlu7a25t8eiItyg237xpbzpjWhhaeTLUlLp/Y=",
		"HOwolK6UGX4EE4a4q3DrlPM0leDauuLOijYqO1tnCwc="
	local p = "hello"
	-- test encr, decr
	local e = cbox.encr(kb, p)
	local p2, m = cbox.decr(kb, e)
	assert(p == p2)
	-- test pken, pkde
	e = cbox.pken(skb, pkb, p)
	p2, m = cbox.pkde(skb, pkb, e)
	assert(p == p2)
	-- test apken, apkde
	e = cbox.apken(pkb, p)
	print(e)
	p2, m = cbox.apkde(skb, e)
	print(#e, p2, m)
	assert(p == p2)
end

------------------------------------------------------------------------
--~ print(cbox.test())

return  cbox

