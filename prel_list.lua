
he = require'he'

local function keys(t)
	local st = {}
	for k, v in pairs(t) do table.insert(st, k) end
	return st
end

local function sortedkeys(t)
	st = keys(t)
	table.sort(st)
	return st
end

print("")
for i, lib in ipairs(keys(package.preload)) do
	kl = sortedkeys(require(lib))
	table.sort(kl)
	print(string.format("%s --- (%d) %s\n", lib, #kl, table.concat(kl, ", ")))
--~ 	print(string.format("%s\n", table.concat(kl, ", ")))
--~  	print("...", table.concat(keys(require(lib)), ", "))
end


