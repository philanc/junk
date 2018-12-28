-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[ 

=== rxs


]]


------------------------------------------------------------------------
-- tmp path adjustment
package.path = "../he/?.lua;" .. package.path

------------------------------------------------------------------------
-- imports and local definitions

local he = require 'he'
rx = require 'rx'



rxs = {}

-- bind raw address  (localhost:3090)
rxs.rawaddr = '\2\0\x0c\x12\127\0\0\1\0\0\0\0\0\0\0\0'
-- bind_address = '::1'    -- for ip6 localhost

-- server state - server exits loop and returns rxs.must_exit
-- if rxs.must_exit is true. (convention: 0 for exit, 1 for exit+reload)
rxs.must_exit = nil

rx.server_set_defaults(rxs)

-- debug_mode (true => request handler is executed without pcall()
-- => a command handler error crashes the server)
rxs.debug_mode = true

rxs.log_already_banned = true

-- server master key
rxs.smk = ('k'):rep(32)

os.exit(rx.serve(rxs)) -- exitcode is the value of rxs.must_exit

