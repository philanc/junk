
--[[



=== args.lua -- command line arguments processing

(tested only on linux with a Bourne shell or similar)

Arguments may have the following forms:
	"key=value" 
		("key=" is interpreted as key=false)
	or key=[ val1 val2 val3 ... ]   (a list of arguments)
		note: "key=[" without spaces, spaces after key=[, and after
		each val, including the last one.
	or "value"  (positional argument)



The function getargs() returns a table with either key=value pairs 
or value=true pairs according to the argument form

the arg[0] and arg[-1] values (lua program name and lua interpreter) 
are not included in the returned table.

for 'key=value' arguments, getargs() attempts to convert the "value" string
to booleans or number if possible:
	"verbose=false"  => verbose = false,
	"verbose=nil"    => verbose = false, (nil cannot be stored)
	"verbose=true"   => verbose = true,
	"count=3"        => count = 3,  -- "3" is converted to integer 3
	conversion to numbers is performaed by the 'tonumber()' function,
	so it works for integers, floats and hex numbers:
		n=123
		n=12.3
		n=0x12a8   are all converted

example:

	program process in=[ fil1 fil2 fil3 ] cnt=3 out=bb.out v= verify
	
	getargs() =>
	{	
	  [1] = "process",
	  [2] = "verify",
	  cnt = 3,
	  v = false,
	  ["in"] = {"fil1", "fil2", "fil3"},
	  out = "bb.out",
	}



]]



local he = require "he"

local insert = table.insert

local function getargs(inargs)
	inargs = inargs or arg  -- default is the Lua arg table
	local argt = {}
	local pi = 1 -- positional argument index
	local inalist = false -- true when collecting a list of values
	local k, v
	local ai = 0 -- arg index
	while ai < #inargs do
		ai = ai + 1
		local a = inargs[ai]
		--
		-- start arg list?
		k = a:match("^([%w%-_]+)=%[$") 
		if k then 
			argt[k] = {}
			while ai < #inargs do
				ai = ai + 1
				a = inargs[ai]
				if a == "]" then break end
				insert(argt[k], a)
				if ai == #inargs then
					return false, "list not closed"
				end
			end
			goto continue
		end
		--
		-- key=value?
		k, v = a:match("^([%w%-_]+)=(.*)$")
		if k then
			if #v == 0 then v = false
			elseif v == "false" then v = false
			elseif v == "true" then v = true
			elseif v == "nil" then v = false --can't store nil...
			elseif tonumber(v) then v = tonumber(v)
			end
			argt[k] = v
			goto continue
		end
		--
		-- here, this is a positional argument
		argt[pi] = a
		pi = pi + 1
		--
	::continue::	
	end
	return argt
end


-- [[ smoke test:

local iat = {"abc", "de=nil", "kl=[", "111", "v2", "]", "ij=", "k",}
--~ local iat = {"abc", "de=fgh", "kl=[", "v1", "v2", "ij=", "k",}
--~ local iat = {"abc", "de=fgh", "kl=[", "]", "ij=", "k",}

local at, msg = getargs(iat)
print(at, msg)
he.pp(at)
he.pp(at.kl)

-- ]]

return getargs  -- this module only returns a function



