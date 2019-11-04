
------------------------------------------------------------------------
local he = require "he"
local b64 = require "plc.base64"

------------------------------------------------------------------------

local sshkeys = require "opensshkeys"

------------------------------------------------------------------------


-- quick test

-- generate a key with:   ssh-keygen -t ed25519 -f aaa
-- it should create two files in current directory ('aaa' the private key, 
-- and 'aaa.pub' the public key)

local sk, pk, pk2, msg, comment, comment2

-- parse the content of the private key file 

local priv = he.fget("aaa")

local sk, pk, comment = sshkeys.parse_private_key(priv)
print("private key comment:", comment)
if not sk then --error
	msg = pk
	print("ERROR:", msg)
	return
end

assert(#pk == 32)
assert(#sk == 32)

-- check that pk is indeed the public key for secret key sk
local lz = require "luazen"
pk2 = lz.x25519_sign_public_key(sk)
assert(pk2==pk)

-- parse the content of the public key file 

local pub = he.fget("aaa.pub")
pk2, comment2 = sshkeys.parse_public_key(pub)
if not pk2 then --error
	msg = comment2
	print("ERROR:", msg)
	return
end
print("public key comment:", comment2)

assert(pk2 == pk)



