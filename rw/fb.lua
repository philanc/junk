-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------
-- Linux framebuffer functions


local l5 = require "l5"
local util = require "l5.util"

local insert, byte, char = table.insert, string.byte, string.char
local spack, sunpack, strf = string.pack, string.unpack, string.format
local errm, rpad, pf, px = util.errm, util.rpad, util.pf, util.px


------------------------------------------------------------------------

fb = {}

local FBIOGET_VSCREENINFO = 0x00004600
local FBIOGET_FSCREENINFO = 0x00004602
local FBIOGETCMAP = 0x00004604
local FB_VISUAL_TRUECOLOR = 0x00000002
local FB_VISUAL_DIRECTCOLOR = 0x00000004
local FB_VISUAL_PSEUDOCOLOR = 0x00000003
local FB_VISUAL_STATIC_PSEUDOCOLOR = 0x00000005

local FB_TYPE_PACKED_PIXELS = 0


fbdevname = "/dev/fb0"

function fb.get_fixinfo(fd)
	local finfo, eno = l5.ioctl(fd, FBIOGET_FSCREENINFO, "", 80)
	return assert(finfo)
end 

function fb.get_varinfo(fd)
	local vinfo, eno = l5.ioctl(fd, FBIOGET_VSCREENINFO, "", 160)
	return assert(vinfo)
end 


--~ return fb

function test_fb_info()
	local fd, eno, em, r
	local finfo, vinfo
	fd, eno = l5.open(fbdevname, 0, 0)
	assert(fd, errm(eno, "open /dev/fb"))
	finfo = fb.get_fixinfo(fd)
	vinfo = fb.get_varinfo(fd)
	local smem_len, fbtype, typeaux, visual = sunpack("I4I4I4I4", finfo, 25) 
--~ 	print(smem_len, type, typeaux, visual)
	if fbtype == FB_TYPE_PACKED_PIXELS then
		print("fb type:", "PACKED PIXELS")
	else
		print("fb type: unknown", fbtype)
	end
	print("fb size:", smem_len)
	if visual == FB_VISUAL_TRUECOLOR then
		print("visual:   ", "TRUECOLOR")
	else
		print("visual: unknown", visual)
	end
	local linelen = sunpack("I4", finfo, 49)
	print("line length:", linelen)
	local xres, yres, xresv, yresv, xoff, yoff, bpp, gray =
		sunpack("I4I4I4I4I4I4I4I4", vinfo)
	print("visible resolution", xres, yres)
	print("virtual resolution", xresv, yresv)
	print("offset            ", xoff, yoff)
	print("bits per pixel    ", bpp)
	print("color=0 else gray ", gray)
	local ro,rlen,rmb,go,glen,gmb,bo,blen,bmb = sunpack(
		"I4I4I4I4I4I4I4I4I4", vinfo, 33)
	print("R/G/B offsets     ", ro, go, bo)
	print("R/G/B lengths     ", rlen, glen, blen)
	print("R/G/B msb is right", rmb, gmb, bmb)
	--
	fbh = assert(l5.fdopen(fd, 'r'))
	fbmem = assert(fbh:read(smem_len))
	print("read:", #fbmem)
	local t = {}
	insert(t, strf("P6 %d %d %d\n", xres, yres, 255))
	for i = 1, smem_len, 4 do
		insert(t, char(
			byte(fbmem, i+2), 
			byte(fbmem, i+1), 
			byte(fbmem, i)
			)
		)
	end
	local s = table.concat(t)
	util.fput("fb.ppm", s)
	assert(l5.close(fd))
end --test_fb_info

function test_fb_dump()
	local fd, eno, em, r
	local finfo, vinfo
	fd, eno = l5.open(fbdevname, 0, 0)
	assert(fd, errm(eno, "open /dev/fb"))
	finfo = fb.get_fixinfo(fd)
	vinfo = fb.get_varinfo(fd)
	local smem_len, fbtype, typeaux, visual = sunpack("I4I4I4I4", finfo, 25) 
--~ 	print(smem_len, type, typeaux, visual)
--~ 	if fbtype == FB_TYPE_PACKED_PIXELS then
--~ 		print("fb type:", "PACKED PIXELS")
--~ 	else
--~ 		print("fb type: unknown", fbtype)
--~ 	end
--~ 	print("fb size:", smem_len)
--~ 	if visual == FB_VISUAL_TRUECOLOR then
--~ 		print("visual:   ", "TRUECOLOR")
--~ 	else
--~ 		print("visual: unknown", visual)
--~ 	end
	local linelen = sunpack("I4", finfo, 49)
--~ 	print("line length:", linelen)
	local xres, yres, xresv, yresv, xoff, yoff, bpp, gray =
		sunpack("I4I4I4I4I4I4I4I4", vinfo)
--~ 	print("visible resolution", xres, yres)
--~ 	print("virtual resolution", xresv, yresv)
--~ 	print("offset            ", xoff, yoff)
--~ 	print("bits per pixel    ", bpp)
--~ 	print("color=0 else gray ", gray)
	local ro,rlen,rmb,go,glen,gmb,bo,blen,bmb = sunpack(
		"I4I4I4I4I4I4I4I4I4", vinfo, 33)
--~ 	print("R/G/B offsets     ", ro, go, bo)
--~ 	print("R/G/B lengths     ", rlen, glen, blen)
--~ 	print("R/G/B msb is right", rmb, gmb, bmb)
	--
	fbh = assert(l5.fdopen(fd, 'r'))
	fbmem = assert(fbh:read(smem_len))
--~ 	print("read:", #fbmem)
	local t = {}
	insert(t, strf("P6 %d %d %d\n", xres, yres, 255))
	for i = 1, smem_len, 4 do
		insert(t, char(
			byte(fbmem, i+2), 
			byte(fbmem, i+1), 
			byte(fbmem, i)
			)
		)
	end
	local s = table.concat(t)
	util.fput("fb.ppm", s)
	assert(l5.close(fd))
end --test_fb_dump

------------------------------------------------------------------------

--~ test_fb_info()

test_fb_dump()
