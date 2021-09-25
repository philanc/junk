
-- 210924   ple7


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

local strf = string.format

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


-- minimal menu function (210925)

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



-- ALTERNATIVE BINDINGS


editor.bindings_ctlx[17] = e.exiteditor -- esc-q, ^X^Q
editor.bindings_ctlx[15] = e.outbuffer -- esc-o, (^O issue w/ mc)


------------------------------------------------------------------------
-- append some text to the initial message displayed when entering
-- the editor
editor.initmsg = editor.initmsg .. " ----- PLE7 / ple_init.lua loaded. "
