
local he = require "he"
local b64 = require "plc.base64"
local pk = he.fget("aaa.pub")

local pkl = he.split(pk)

--~ he.pp(pkl)
--~ print(pkl[1], pkl[3])
local ks = b64.decode(pkl[2])
--~ print(he.repr(ks))
--~ print(#k)
local kalgo, k = string.unpack(">s4s4", ks)
--~ print(#kalgo, kalgo, "#key:", #k)
--~ print(b64.encode(k))


local function parse_ssh_private_key(txt)
	-- parse an openssh-generated private key file content
	-- return the secret and public keys (as 32-byte binary strings)
	-- or nil, errmsg if text cannot be parsed
	local pat = "%-%-%-%-%-BEGIN OPENSSH PRIVATE KEY%-%-%-%-%-"
		..  "(.+)"
		..  "%-%-%-%-%-END OPENSSH PRIVATE KEY%-%-%-%-%-"
	local bk = txt:match(pat)
	if not bk then return nil, "invalid header/footer" end
	bk = b64.decode(bk)
	if not bk then return nil, "invalid base64" end
	local r = bk:match("openssh%-key%-v1\0")
	if not r then return nil, "invalid keyfile version" end
	-- hack! don't parse everything. look for the _last_ "ssh-ed25519"
	bk = bk:gsub("openssh%-key%-v1\0.+ssh%-ed25519", "")
	local pubk, privk, comment = string.unpack(">s4s4s4", bk)
	assert(#privk == 64)
	-- the privkey is always the secret key (32-byte) with the
	-- public key (32-byte) concatenated at the end
	local sk, pk = privk:sub(1, 32), privk:sub(33)
	assert(pk == pubk)
	return sk, pk, comment
end --parse_ssh_private_key()

local function parse_ssh_public_key(txt)
	-- return the public key (as a binary string)
	-- and the key comment if any
	local pkl = he.split(txt)
	if not pkl[2] then return nil, "invalid content" end
	local comment = pkl[3]
	local ks = b64.decode(pkl[2])
	local algo, pk = string.unpack(">s4s4", ks)
	if algo ~= "ssh-ed25519" then 
		return nil, "not a ssh-ed25519 key" 
	end
	return pk, comment
end --parse_ssh_public_key()

------------------------------------------------------------------------
-- quick test

-- generate a key with:   ssh-keygen -t ed25519 -f aaa
-- it should create two files in current directory ('aaa' the private key, 
-- and 'aaa.pub' the public key)

local sk, pk, pk2, msg, comment, comment2

-- parse the content of the private key file 

local priv = he.fget("aaa")

local sk, pk, comment = parse_ssh_private_key(priv)
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
pk2, comment2 = parse_ssh_public_key(pub)
if not pk2 then --error
	msg = comment2
	print("ERROR:", msg)
	return
end
print("public key comment:", comment2)

assert(pk2 == pk)



