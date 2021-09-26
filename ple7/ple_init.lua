
-- ple7:  git ple with minor changes and additions defined in ple_init.lua


-- 210926  replace ple7 w/ git ple.  move all changes to ple_init
-- 210925  initial junk/ple7

-- a sample PLE configuration / extension file
------------------------------------------------------------------------
-- The configuration file is looked for in sequence at the
-- following locations:
--	- the file which pathname is in the environment variable PLE_INIT
--	- ./ple_init.lua
--	- ~/config/ple/ple_init.lua
--
--The first file found, if any, is loaded.
------------------------------------------------------------------------
-- local defs

local strf = string.format

local e = editor.actions
local msg = editor.msg

------------------------------------------------------------------------
-- ple modifications


-- prefix handling (210924)
--	esc def as alias to ctlx
--	after ctlx or esc, lower-case letters converted to ctl-char
--	  so esc-a = ^X^A, (but esc-A = ^XA), esc-m = esc-ret = ^X^M, ...
--	backquote was defined as alias to esc. removed 210926.

e.prefix_ctlx = function(b)
	-- process ^X prefix
	local k = editor.nextk()
	--210924  a..z converted to ^A..^Z
	if k >= 97 and k <= 122 then 
		k = k - 96
	end
	local kname = "^X-" .. editor.keyname(k)
	local act = editor.bindings_ctlx[k]
	if not act then
		msg(kname .. " not bound.")
		return false
	end
	msg(kname)
	return act(b)
end--prefix_ctlx

-- (re)bind prefix_ctlx
editor.bindings[24] = e.prefix_ctlx
editor.bindings[27] = e.prefix_ctlx
			


------------------------------------------------------------------------
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

-- all editor.actions functions take a buffer object as first parameter
-- and additional parameters for some functions.
-- A common error is to call an editor.actions function without the buffer
-- object as first parameter (see examples below).


-- QUICK EXIT -- DOESN'T CHECK MODIFIED BUFFERS

-- nice for tests. Remove it for day to day usage!!

function e.quiteditor(b)
	editor.quit = true
end

-- comment next line for day to day usage
editor.bindings_ctlx[17] = e.quiteditor	-- esc-q, ^X^Q



-------------------------------------------------------------------------- SHELL 

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
	if #ll ~= 0 then 
		e.insert(b, ll)
	end
	-- insert another newline and a separator line
	e.nl(b)
	e.insert(b, '---\n')
		-- the previous line is equivalent to
		-- e.insert(b, '---'); e.nl(b)
end

-- bind the line_shell function to ^X^M (or ^X-return)
editor.bindings_ctlx[13] = line_shell


-- EDIT FILE AT CURSOR

-- assume the current line contains a filename.
-- get the filename and open the file in a new buffer
--
local function edit_file_at_cursor(b)
	local line = e.getline(b)
	-- (FIXME) assume the line ends with the filename
	local i, j, fname = line:find("(%S+)%s*$")
	if fname and #fname > 0 then 
		e.findfile(b, fname)
	else
		editor.msg("No file name found")
	end
end

-- bind function to ^Xe (string.byte"e" == 101)
-- bind function to ^X^E (string.byte"e" == 101)
editor.bindings_ctlx[5] = edit_file_at_cursor -- ^X^E, esc-e


------------------------------------------------------------------------
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
-- bind function to ^X^L (esc-l) 
editor.bindings_ctlx[12] = e.eval_lua_buffer -- esc-l, ^X^L


------------------------------------------------------------------------
-- INSERT DATE + ITEM

function e.insert_date(b)
	e.insert(b, os.date("%y%m%d "))
end

function e.insert_dated_item(b)
	e.goeot(b)
	e.nl(b)
	e.nl(b)
	e.insert(b, os.date("=== %y%m%d "))
end

editor.bindings[29] = e.insert_date       -- ^5 or ^]
editor.bindings[31] = e.insert_dated_item -- ^7 or ^_


------------------------------------------------------------------------
-- BUFFER ENCRYPTION

local moe = require "he.moe"

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
-- MENU TESTS 

--minimal menu function (210925)

function e.menu(b, txt, actbl)
	local ch = editor.readchar(txt, ".")
	if not ch then editor.msg("aborted!"); return end
	local action = actbl[ch]
	if not action then
		editor.msg("??? unknown option.")
	else
		editor.msg("")
		action(b)
	end
end
			
function e.menu0(b, txt, actbl)
	local pr = "    " .. txt
	while true do
		local ch = editor.readchar(pr, ".")
		if not ch or ch == "q" then editor.msg("aborted!"); break end
		local action = actbl[ch]
		if not action then
			pr = "??? " .. txt
		else
			editor.msg("")
			action(b)
			break
		end
	end
end
			
-- test menu
function e.testmenu(b)
	e.menu(b, "test menu - Buf Nextbuf Prevbuf Findfile Yyy Zzz Quit", {
		["y"] = function(b) e.insert(b,"YYY\n") end,
		["z"] = function(b) e.insert(b,"ZZZ\n") end,
		["n"] = e.nextbuffer,
		["p"] = e.prevbuffer,
		["b"] = e.newbuffer,
		["f"] = e.findfile,
	})
end

editor.bindings_ctlx[20] = e.testmenu -- esc-t




------------------------------------------------------------------------
-- ALTERNATIVE BINDINGS

editor.bindings_ctlx[15] = e.outbuffer -- esc-o, (^O issue w/ mc)


------------------------------------------------------------------------
-- append some text to the initial message displayed when entering
-- the editor
editor.initmsg = editor.initmsg .. " ----- PLE7 / ple_init.lua loaded. "
