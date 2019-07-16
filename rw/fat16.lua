-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[

FAT16 support functions

Assumes 512-byte sectors

All integers are little endians

a good reference:
https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system


]]


local l5 = require "l5"
local util = require "l5.util"

local insert, byte, char = table.insert, string.byte, string.char
local spack, sunpack, strf = string.pack, string.unpack, string.format
local errm, rpad, pf, px = util.errm, util.rpad, util.pf, util.px


------------------------------------------------------------------------

fat16 = {}


function makeimg(size, diskid, label)
	-- make a FAT16-formatted disk image
	-- return the image as a string
end

function bootsector(size, diskid, label)
	-- head is x86 inst to ump to boot code
	-- is it used as a signature?  
	local nbsec = size // 512 -- total number of sectors
	local nbclusec = 4 -- numbr of sector per cluster
	local nbfatsec = 40 -- number of sectors in each fat
	local st = {
	"\xeb\x3c\x90", -- jmp rel +3c, nop
	"mkfs.fat", 	-- OEM name
	"\x00\x02", 	-- nb bytes per sector = 512
	"\x04", 	-- nb sector per cluster = 4 (variable)
	"\x01\x00", 	-- nb of reserved sectors (1 - the boot sector)
	"\x02", 	-- nb of FAT (2)
	"\x40\x00",	-- nb of entries in root dir (64)
	"\x00\x00",	-- 0 => look for nb of sectors at at 0x0020
	"\xf8", 	-- media id (f8 for hard disk)
	spack("<I2", nbfatsec),	-- nb of sectors per fat (variable)
	"\x20\x00",	-- nb of sectors per track (ignored?) 
	"\x40\x00",	-- nb of heads (ignored?)
	"\x00\x00\x00\x00", -- unpartitioned media, unused
	spack("<I4", nbsec),
	"\x80",		-- physical drive number (80=1st hard disk)
	"\x00\x29",	-- reserved, extended boot signature (0x29)
	spack("<I4", diskid),
	rpad(label, 11, " "),
	"FAT16   ", 	-- fs type, padded with spaces (char[8])
	("\0"):rep(448),  -- reserved space for the boot code
			  -- starts at offset 0x003e
	"\x55\xaa",	-- end of boot sector signature
	}
	local s = table.concat(st)
	assert(#s == 512)
	return s
end

function emptyfat(nbfatsec)
	-- f8ff - FAT16 id
	-- ffff - end of cluster chain marker
	return rpad("\xf8\xff\xff\xff", nbfatsec * 512, "\0")
end




--~ return fat16

------------------------------------------------------------------------
-- tests

require"hei"
size = 20*1024*1024
diskid = 0x89abcdef
label = "ABCDEF"
s = bootsector(size, diskid, label)
pix(#s)
pix(#emptyfat(0x28))




