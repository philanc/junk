-- Copyright (c) 2019  Phil Leblanc  -- see LICENSE file
------------------------------------------------------------------------

--[[

cio - coroutine-based concurrent I/O for l5




]]


require'he.i'

local l5 = require "l5"
local util = require "l5.util"

local spack, sunpack, strf = string.pack, string.unpack, string.format
local errm, rpad, pf = util.errm, util.rpad, util.pf

local insert, remove = table.insert, table.remove
local yield, resume = coroutine.yield, coroutine.resume


local NOTIMEOUT = math.maxinteger -- (a value larger than any time)
local NODEADLINE = math.maxinteger -- (a value larger than any time)



------------------------------------------------------------------------

cio = {}

local tasklist = {} -- list of all tasks created by cio
local taskmap = {} -- map coroutines to tasks (used to find the current task)

function cio.newtask(f, name)
	local co = coroutine.create(f)
	name = name or tostring(co)
	-- f signature: f(task) -> true or nil, errmsg
	-- when the coroutine is resumed, the task object is passed to it
	local task = {co=co, name=name, ready=true, deadline=NODEADLINE}
	insert(tasklist, task)
	taskmap[co] = task
	return task
end --newtask

function cio.curtask()
	-- return the current task. 
	-- errors if the current coroutine is not a registered task.
--~ 	print("CUR", coroutine.running())
	local co, is_main = coroutine.running()
	return assert(not is_main and taskmap[co], "cio: no current task")
end
	

local function runtask(i)
	-- run task at index i in tasklist
	-- on error or if the task has completed, it is removed from 
	-- tasklist. else, the task is moved at end of tasklist. 
	-- return true or nil, errmsg in case of error
	local task = tasklist[i]
	local r, errmsg = resume(task.co, task)
	remove(tasklist, i)
	if coroutine.status(task.co) ~= "dead" then
		insert(tasklist, task) -- insert at end of tasklist
	else 
		-- the coroutine is dead. remove from taskmap:
		taskmap[task.co] = nil
	end
	if r then return true else return nil, errmsg end
end --runtask
	
function cio.step()
	local r, errmsg
	local now = os.time()
	-- find the first task ready to run
	for i = 1, #tasklist do
		local task = tasklist[i]
		-- check deadline
		if task.deadline <= now then
			task.st = "timeout"
			task.ready = true
		end
		if task.ready then
			-- run the task
			print("resuming task", i, task.name)
			r, errmsg = runtask(i)
			print("r, name, st, arg", task.name, task.st, task.arg)
			if not r then 
				print("error:", task.name, errmsg)
			end
			return r, errmsg
		end
	end--for
	-- here, no ready task. => wait a bit
	return nil, "nothing to run"
end	

function cio.loop()
	local r, errmsg
	while not cio.finished do
		r, errmsg = cio.step()
		if not r and errmsg == "nothing to run" then
--~ 			print("cio.loop: nothing to run")
			print("[]")
			l5.msleep(1000)
		end
	end
end

function cio.sleep(sec)
	local task = cio.curtask()
	local now = os.time()
	task.deadline = now + sec
	task.ready = false
	return true
end

function cio.recv(fd, n, timeout)
	-- read n bytes on file descriptor fd
	-- optional timeout (in seconds). default is no timeout
	
end

------------------------------------------------------------------------
-- non-blocking I/O


------------------------------------------------------------------------
function test1()
	function tf1(task)
		print("EQUAL??", cio.curtask(), task)
		task.ready = true
		local i = 10
		while i > 0 do
			i = i - 1
--~ 			print("CURTASK >", cio.curtask().name)
			cio.sleep(5)
			print(cio.curtask().name, os.time())
--~ 			if i == 5 then error("ERROR!!!") end 
			task.arg = i
			yield()
		end
		print("tf1 completed.")
		cio.finished = true
	end--tf1()
	function tf2(task)
		task.ready = true
		local i = 100
		while i > 90 do
			i = i - 1
--~ 			print("tf2")
			cio.sleep(3)
			print('\t\t\t\t', cio.curtask().name, os.time())
			task.arg = i
			yield()
		end
		print("tf2 completed.")
--~ 		cio.finished = true
	end--tf1()
	cio.newtask(tf1, "tf1")
	cio.newtask(tf2, "tf2")
	pp(taskmap)
	cio.loop()
end

test1()
------------------------------------------------------------------------
return cio	
