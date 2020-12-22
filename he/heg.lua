
-- convenience definitions for interactive Lua sessions

-- make he global
he = require "he"  -- make he global

-- add he string functions to string metatable
he.extend_string()

-- make all he definitions global
for k, v in pairs(he) do 
	if _G[k] and (_G[k] ~= v) then 
		print(k .. " is already defined in _G")
	else
		_G[k] = v 
	end
end
print(he.VERSION, "all he definitions are now global.")



