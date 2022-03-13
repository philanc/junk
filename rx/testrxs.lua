-- test rx server
local rxs = require"rxs"
local util = require "util"
local lm = require 'luamonocypher'

local r, err, mpk

-- set test mpk
mpk = "scjw0/N27iK/dF3isZ09hKmYNqqmk271tpXSkLu5EGM="
mpk = assert(lm.b64decode(mpk))

-- init server 

local server = {
	mpk = mpk,
	port = 4096,
}

assert(rxs.serverinit(server))

-- run server
rxs.runserver(server)

