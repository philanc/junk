
-- a test configuration / extension file for ple
------------------------------------------------------------------------
-- The configuration file is looked for in sequence at the 
-- following locations:
--	- the file which pathname is in the environment variable PLE_INIT
--	- ./ple_init.lua
--	- ~/config/ple/ple_init.lua
--
--The first file found, if any, is loaded. 
------------------------------------------------------------------------

local he = require "he"
local moe = require "he.moe"

local strf = string.format

local function dbgf(f, ...) editor.dbg(strf(f, ...)) end

-- Configuration

-- Configuration variables and editor extension API are available
-- through the 'editor' global object.

-- editor.tabspaces: defines how the TAB key should be handled.  
--      n:integer :: number of spaces to insert when the TAB key is pressed
--                   (according to cursor position)
--                   eg.:  editor.tabspaces = 4
--      or false  :: insert a TAB char (0x09) when the TAB key is pressed
--                   eg.:  editor.tabspaces = false

editor.tabspaces = 8

-- Extension API -- when writing extensions, it is recommended to use only 
-- functions defined in the editor.actions table (see ple.lua)
local e = editor.actions

-- all editor.actions functions take a buffer object as first parameter
-- and additional parameters for some functions.
-- A common error is to call an editor.actions function without the buffer
-- object as first parameter (see examples below).


------------------------------
-- QUICK EXIT -- DOESN'T CHECK MODIFIED BUFFERS

function e.quiteditor(b)
	editor.quit = true
end

editor.bindings[17] = e.quiteditor	-- ^Q


------------------------------
-- SHELL command
-- Add a new action "line_shell" which takes the current line,
-- passes it as a command to the shell and inserts the result 
-- after the current line.

local function line_shell(b)
	-- the function will be called with the current buffer as
	-- the first argument. So here, b is the current buffer.
	--
	-- get the current line 
	local line = e.getline(b) 
	-- the shell command is the content of the line 
	local cmd = line
	-- make sure we also get stderr...
	cmd = cmd .. " 2>&1 "
	-- execute the shell command
	local fh, err = io.popen(cmd)
	if not fh then
		editor.msg("newline_shell error: " .. err)
		return
	end
	local ll = {} -- read lines into ll
	for l in fh:lines() do
		table.insert(ll, l)
	end
	fh:close()
	-- go to end of line 
	-- (DO NOT forget the buffer parameter for all e.* functions)
	e.goend(b)
	-- insert a newline at the cursor
	e.nl(b)
	-- insert the list of lines at the cursor
	-- e.insert() can be called with either a list of lines or a string
	-- that may contain newlines ('\n') characters
	-- lines should NOT contain '\n' characters
	e.insert(b, ll)
	-- insert another newline and a separator line
	e.nl(b)
	e.insert(b, '---\n') 
		-- the previous line is equivalent to 
		-- e.insert(b, '---'); e.nl(b)
end	

-- bind the line_shell function to ^X^M (or ^X-return)
editor.bindings_ctlx[13] = line_shell

------------------------------
-- EDIT FILE AT CURSOR
-- assume the current line contains a filename.
-- get the filename and open the file in a new buffer
--
local function edit_file_at_cursor(b)
	local line = e.getline(b)
	-- (FIXME) assume the line contains only the filename
	local fname = line
	e.findfile(b, fname)
end

-- bind function to ^Xe (string.byte"e" == 101)
editor.bindings_ctlx[101] = edit_file_at_cursor -- ^Xe

------------------------------
-- EVAL LUA BUFFER
-- eval buffer as a Lua chunk 
-- 	Beware! the chunk is evaluated **in the editor environment**
--	which can be a way to shoot oneself in the foot!
-- chunk evaluation result is inserted  at the end 
-- of the buffer in a multi-line comment.

function e.eval_lua_buffer(b)
	local msg = editor.msg 
		-- msg(m) can be used to diplay a short message (a string)
		-- at the last line of the terminal
	local strf = string.format
	
	-- get the number of lines in the buffer
	-- getcur() returns the cursor position (line and column indexes)
	-- and the number of lines in the buffer.
	local ci, cj, ln = e.getcur(b) -- ci, cj are ignored here.
	-- get content of the buffer 
	local t = {}
	for i = 1, ln do
		table.insert(t, e.getline(b, i))
	end
	-- txt is the content of the buffer as a string
	local txt = table.concat(t, "\n")
	-- eval txt as a Lua chunk **in the editor environment**
	local r, s, fn, errmsg, result
	fn, errmsg = load(txt, "buffer", "t") -- load the Lua chunk
	if not fn then 
		result = strf("load error: %s", errmsg)
	else
		pr, r, errm = pcall(fn)
		if not pr then 
			result = strf("lua error: %s", r)
		elseif not r then 
			result = strf("return: %s, %s", r, errmsg)
		else
			result = r
		end
	end
	-- insert result in a comment at end of buffer
	e.goeot(b)	-- go to end of buffer
	e.nl(b) 	-- insert a newline
	--insert result
	e.insert(b, strf("--[[\n%s\n]]", tostring(result)))
	return

	
end
-- bind function to ^Xl  (string.byte"l" == 108)
editor.bindings_ctlx[108] = e.eval_lua_buffer -- ^Xl

------------------------------
-- INSERT DATE

function e.insert_date(b)
	e.insert(b, os.date("%y%m%d "))
end

function e.insert_date_sec(b)
	e.goeot(b)
	e.nl(b)
	e.nl(b)
	e.insert(b, os.date("=== %y%m%d "))
end

editor.bindings[29] = e.insert_date -- ^5 or ^]
editor.bindings[31] = e.insert_date_sec -- ^7 or ^_



------------------------------------------------------------------------
-- BUFFER ENCRYPTION

local function gettext(b)
	return table.concat(b.ll, "\n")
end

local function settext(b, txt)
	-- !! clear all the buffer undo list
	return b:settext(txt)
end

local function be_wrap(pt)
	return moe.encrypt(editor.be_key, pt, true)
end

local function be_unwrap(et)
	local pt = moe.decrypt(editor.be_key, et, true)
	if not pt then return nil, "decrypt error" end
	return pt
end

local function be_doit(b)
	local errmsg
	local k = editor.be_key
	local bt = gettext(b)
	local kt = bt:match("^ck=([^\r\n]+)")
	if kt then -- set key
		k = moe.stok(kt)
		editor.be_key = k
		settext(b, "") -- clear buffer and erase undo history
		editor.msg("*** key set ***")
		return true
	end
	if (not k) or (k == "") then 
		editor.msg("*** key not defined ***")
		return false
	end	
	local pflag = bt:match("^%-%-ck%s")
	if pflag then 
		settext(b, be_wrap(bt))
		b.be_plain = false
	else
		bt, errmsg = be_unwrap(bt)
		if bt then
			settext(b, bt)
			b.be_plain = true
		else
			editor.msg("*** invalid buffer *** " .. errmsg)
		end
	end
end --be_doit

-- trap e.savefile  -- [should also trap e.writefile]
local core_savefile = e.savefile

e.savefile = function(b)
	if b.be_plain then 
		editor.msg("*** cannot save file as-is ***")
		return false
	end
	return core_savefile(b)
end
	
editor.bindings_ctlx[19] = e.savefile -- ^X^S
editor.bindings_ctlx[57] = be_doit -- ^X9




------------------------------------------------------------------------
-- SECTIONS

--[[

A section
- starts at bot, or with '===' at bol , 
- ends just before the next '===' line or at eot 

functions
	selsec  - set cur at bosel, mark at eosel
	luasec  - eval section as a lua chunk
	getsec  - return content of current section as a string
	getsecl - return content of current section as a list of lines
	prevsec
	nextsec
	
	
]]

local function atbosec(b, i)
	local l = b:getline(i)
	return l and l:match("^===")
end

local function bosec(b, i)
	-- return index of 1st line of section containing line i
	-- or idx of first line
	while i >= 1 do
		if atbosec(b, i) then return i end
		i = i - 1
	end--while
	return 1
end --bosec()

local function eosec(b, i)
	-- return line idx of end of section
	-- (or idx of last buffer line)
	local bln = #b.ll
	
	while i <= bln do
		i = i + 1
		if atbosec(b, i) then return i - 1 end
	end--while
	return bln
end --goeosec()

local function getsecl(b)
	local ci, cj = b:getcur()
	local bi, ei = bosec(b, ci), eosec(b, ci)
	local ei, bi = eosec(b, ci), bosec(b, ci)
--~ 	local ds = sf(">>>getsecl bi=%d  ei=%d", bi, ei)
	local sl = {}
	for i = bi, ei do
		table.insert(sl, b.ll[i])
	end
	return sl
end

local function getsec(b)
	local sl = getsecl(b)
	return table.concat(sl, "\n")
end


function e.testsec(b)
	local sl = getsecl(b)
	local ob = e.newbuffer(b, "*OUT*")
	e.goeot(ob)
--~ 	e.insert(ob, {"", "=== OUT"})
	e.insert(ob, sl)
end

function e.prevsec(b)
	local ci, cj = b:getcur()
	local i = ci
	if atbosec(b, i) then i = i -1 end
	i = bosec(b, i)
	if not i then return false end
	b:setcur(i, 0)
	return true
end

function e.nextsec(b)
	local ci, cj = b:getcur()
	local i = ci
	if atbosec(b, i) then i = i + 1 end
	i = eosec(b, i)
	if not i then return false end
	b:setcur(i+1, 0)
	return true
end

-- eval current section as a Lua chunk (in the editor environment)
-- if the chunk returns a string, it is inserted  at the end 
-- of the buffer in a multi-line comment

function e.eval_lua_section(b)
	local msg = editor.msg
	local strf = string.format
	local txt = getsec(b)
	txt = '-- ' .. txt -- comment 1st line ("=== ...")
	local r, s, fn, errm
	fn, errm = load(txt, "buffer", "t") -- chunkname=buffer, mode=text only
	if not fn then 
		msg(errm)
	else
		pr, r, errm = pcall(fn)
		if not pr then msg(strf("lua error: %s", r)); return end
		if not r then msg(strf("return: %s, %s", r, errm)); return end
		local ob = e.newbuffer(b, "*OUT*")
		e.goeot(ob)
	 	e.insert(ob, {"", "===", ""})
		e.insert(ob, strf("\n%s\n", tostring(r)))
--~ 		editor.fullredisplay(b)
		return
	end
end

-- bindings
editor.bindings_ctlx[91] = e.prevsec -- ^X[
editor.bindings_ctlx[93] = e.nextsec -- ^X]



--~ editor.bindings_ctlx[57] = e.crypto -- ^X9
editor.bindings_ctlx[12] = e.eval_lua_section -- ^X^L
editor.bindings_ctlx[116] = e.testsec -- ^Xt

------------------------------------------------------------------------
--[[    ctl mode

- lowercase letters [a-z] are turned into their ctrl-equivalent
	eg. 'a' is mapped to ^A
	so 'xa' is equivalent to ^X^A in normal mode

- Other printable chars do no longer auto-insert. They can be bound 
  directly to actions in table 'editor.bindings_ctlmode'

- 'space' ends ctl mode and switch back to normal mode.


CAUTION: to support ctl mode, the ^X processing is modified.
	 Now, for any lowercase letter 'a', ^Xa is turned into ^X^A
	 So ^X^A and ^Xa can no longer be bound to different actions!!

]]

function e.prefix_ctlx_ctlmode(b)
	-- redefine the ^X prefix processing:
	-- if the key pressed after ^X is a lowercase letter, 
	-- it is turned into the corresponding Control-char, 
	-- eg.: 'a' is turned into ^A  --  so ^Xa is the same as ^X^A
	local k = editor.nextk()
	if k >= 97 and k <= 122 then -- k is in range [a-z]
		k = k - 96 -- k is now in range [^A-^Z]
	end
	local kname = "^X-" .. editor.keyname(k)
	local act = editor.bindings_ctlx[k]
	if not act then
		editor.msg(kname .. " not bound.")
		return false
	end
	editor.msg(kname)
	return act(b)	
end--prefix_ctlx_ctlmode

editor.bindings[24] = e.prefix_ctlx_ctlmode  -- new ^X binding

-- additional bindings specific to ctl mode
editor.bindings_ctlmode = {}


function e.ctlmode(b)
	editor.dbg("CTLMODE") -- add indicator to statusline
	editor.in_ctlmode = true
	editor.fullredisplay()
	while editor.in_ctlmode and not editor.quit do
		local k = editor.nextk()
		if k == 32 then -- space - exit ctl mode
			break
		end
		if k >= 97 and k <= 122 then -- k is in range [a-z]
			k = k - 96 -- k is now in range [^A-^Z]
		end
		local act = editor.bindings_ctlmode[k] or editor.bindings[k]
		local kname = editor.keyname(k)
		if not act then
			editor.msg(kname .. " not bound.")
		else
			editor.msg(kname)
			act(editor.buf)	
		end
		editor.redisplay(editor.buf)

	end--while
	editor.dbg("") -- clean status line
end--ctlmode

--~ editor.bindings[3] = e.ctlmode  -- ^C - temp binding

editor.bindings[96] = e.ctlmode  -- backquote

editor.bindings_ctlmode[96] = function(b) -- backquote
	e.insert(b, "`")
--~ 	editor.in_ctlmode = nil
	end

editor.bindings_ctlmode[91] = e.prevsec -- [
editor.bindings_ctlmode[93] = e.nextsec -- ]

editor.bindings_ctlmode[61] = e.eval_lua_section -- '='

------------------------------------------------------------------------
-- misc

-- test key

local function insertateot(b, s)
	e.goeot(b); e.nl(b);
	e.insert(b, s)
	editor.redisplay(b)
end --insertateot

function e.testk(b)
	-- test readkey
	insertateot(b, "test read key (space to quit):")
	while true do
		local k = editor.nextk()
		local kname = editor.keyname(k)
		if k == 32 then break end
		local m = strf("%d\t%s", k, tostring(kname))
		insertateot(b, m)
	end
	editor.msg("Aborted!")
end--atest

editor.bindings[20] = e.testk		-- ^T


------------------------------------------------------------------------
-- append some text to the initial message displayed when entering
-- the editor
editor.initmsg = editor.initmsg .. " - ppeinit.lua 200904 loaded. "
