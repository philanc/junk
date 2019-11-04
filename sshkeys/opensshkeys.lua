-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[ 

opensshkeys.lua - parsing OpenSSH ed25519 key files

parse_private_key   - parse an unencrypted private key file content
parse_public_key    - parse a public key file content

Notes:

- keys are returned as binary strings (no hex or base64 encoding).

- here, the raw secret key is returned (a 32-byte binary string) 
  contrary to the usual APIs where the public key (32-byte) is 
  concatenated at the end of the private key, for a total private key 
  length of 64 bytes. 

]]
------------------------------------------------------------------------
local he = require "he"
local b64 = require "plc.base64"

------------------------------------------------------------------------

local sshkeys = {}

function sshkeys.parse_private_key(txt)
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
end --parse_private_key()

function sshkeys.parse_public_key(txt)
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
end --parse_public_key()

------------------------------------------------------------------------
return sshkeys

