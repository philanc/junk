-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
--[[

FAT16 - simplest code to make an image of a FAT16-formatted filesystem



Notes:

- a good reference is the wikipedia page:
https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system

- to keep the code simple some parameters are fixed:
	- the code assumes 512-byte sectors
	- cluster size: 8 sectors (4 kbytes)
		=> max volume size < 256 mbytes
	- number of entries in the root directory: 64
	- the boot code is ignored (set to zero)
	- the API allows to create only images with a size 
	  multiple of 1 mbytes (it eliminates the rounding issues)

- all integers are stored little endian

- the root directory is completely empty. the code doesn't insert 
  an entry with the volume label

  
]]


local l5 = require "l5"
local util = require "l5.util"

local insert, byte, char = table.insert, string.byte, string.char
local spack, sunpack, strf = string.pack, string.unpack, string.format
local errm, rpad, pf, px = util.errm, util.rpad, util.pf, util.px
local fget, fput = util.fget, util.fput


------------------------------------------------------------------------

fat16 = {}


local function emptyfat(nbfatsec)
	-- return an empty fat as a string
	-- nbfatsec is the number of sectors used by the fat
	-- f8ff - FAT16 id
	-- ffff - end of cluster chain marker
	return rpad("\xf8\xff\xff\xff", nbfatsec * 512, "\0")
end

function fat16.header(sizemb, diskid, label)
	-- return the header of a FAT16 filesystem image
	-- (including the boot sector and two FATs and the root directory)
	-- sizemb is the image size in MBytes (eg. 10 for a 10MB image)
	-- diskid is the disk identifier (or serial number) as an integer
	-- label is the volume label as a string (11 chars or less)
	-- 
	-- limits: the number of sectors per cluster is fixed to 8
	-- (4 KB clusters) so the volume should be less than 256 MB
	assert(sizemb < 256, "size must be less than 256 MBytes")
	local size = sizemb * 1024 * 1024
	local nbsec = size // 512 -- total number of sectors
	local nbclusec = 8  -- number of sectors per cluster
	local clusize = 512 * nbclusec  -- cluster size in bytes 
	local nbclu = nbsec // nbclusec -- total number of clusters
	local fatsize = nbclu * 2 -- size of each fat
	local nbfatsec = fatsize // 512  -- number of sectors in each fat
	local fat1 = emptyfat(nbfatsec)
	local fat2 = fat1
	local rootdir = ('\0'):rep(32 * 64) -- 64 entries of 32 bytes
	local st = {
	-- first bytes are x86 inst to jump to boot code
	-- is it used as a signature?  
	"\xeb\x3c\x90", -- jmp rel +3c, nop (x86 jump to boot code)
	"mkfs.fat", 	-- OEM name
	"\x00\x02", 	-- nb bytes per sector = 512
	spack("I1", nbclusec), 	-- nb sector per cluster = 8 (variable)
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
	fat1,
	fat2,
	rootdir,
	}
	local s = table.concat(st)
	assert(#s == 512 + 2*fatsize + #rootdir)
	return s
end

function fat16.img(sizemb, diskid, label)
	-- return an empty FAT16 filesystem image as a string
	-- sizemb is the image size in MBytes (eg. 10 for a 10MB image)
	-- diskid is the disk identifier (or serial number) as an integer
	-- label is the volume label as a string (11 chars or less)
	local header = fat16.header(sizemb, diskid, label)
	-- the rest of the image is filled with zero.
	local size = sizemb * 1024 * 1024
	return rpad(header, size, "\0")
end


--~ return fat16

------------------------------------------------------------------------
-- tests

require"hei"
sizemb = 100
diskid = 0x89abcdef
label = "ABCDEF"
h = fat16.header(sizemb, diskid, label)
pix(#h)

img=fat16.img(sizemb, diskid, label)
fput("f100", img)






