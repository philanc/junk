/*
* one.c -- Lua core, libraries, and interpreter in a single file (Lua 5.3)
*/

/* default is to build the full interpreter */
#ifndef MAKE_LIB
#ifndef MAKE_LUAC
#ifndef MAKE_LUA
#define MAKE_LUA
#endif
#endif
#endif

/* choose suitable platform-specific features */
/* some of these may need extra libraries such as -ldl -lreadline -lncurses */
/*
#define LUA_USE_LINUX
#define LUA_USE_MACOSX
#define LUA_USE_POSIX
#define LUA_USE_DLOPEN
#define LUA_USE_READLINE
*/

/* other specific features */
/*
#define LUA_32BITS
#define LUA_USE_C89
#define LUA_C89_NUMBERS
*/

/* no need to change anything below this line ----------------------------- */

/* activate system definitions in lprefix.h */
#include "lprefix.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* setup for luaconf.h */
#define LUA_CORE
#define LUA_LIB
#define lvm_c
#include "luaconf.h"



//~ /* do not export internal symbols */
//~ #undef LUAI_FUNC
//~ #undef LUAI_DDEC
//~ #undef LUAI_DDEF
//~ #define LUAI_FUNC	static
//~ #define LUAI_DDEC	static
//~ #define LUAI_DDEF	static

#undef LUAI_FUNC
#define LUAI_FUNC	static
//~ #define LUAI_DDEC(dec)	static dec
#define LUAI_DDEF	static


//~ //===

//~ #include "lapi.h"
//~ #include "lauxlib.h"
//~ #include "lcode.h"
//~ #include "lctype.h"
//~ #include "ldebug.h"
//~ #include "ldo.h"
//~ #include "lfunc.h"
//~ #include "lgc.h"
//~ #include "ljumptab.h"
//~ #include "llex.h"
//~ #include "llimits.h"
//~ #include "lmem.h"
//~ #include "lobject.h"
//~ #include "lopcodes.h"
//~ #include "lopnames.h"
//~ #include "lparser.h"
//~ #include "lprefix.h"
//~ #include "lstate.h"
//~ #include "lstring.h"
//~ #include "ltable.h"
//~ #include "ltm.h"
//~ #include "lua.h"
//~ // #include "luaconf.h"
//~ #include "lualib.h"
//~ #include "lundump.h"
//~ #include "lvm.h"
//~ #include "lzio.h"
//===

/* core -- used by all */
#include "lapi.c"
#include "lcode.c"
#include "lctype.c"
#include "ldebug.c"
#include "ldo.c"
#include "ldump.c"
#include "lfunc.c"
#include "lgc.c"
#include "llex.c"
#include "lmem.c"
#include "lobject.c"
#include "lopcodes.c"
#include "lparser.c"
#include "lstate.c"
#include "lstring.c"
#include "ltable.c"
#include "ltm.c"
#include "lundump.c"
#include "lvm.c"
#include "lzio.c"

/* auxiliary library -- used by all */
#include "lauxlib.c"

/* standard library  -- not used by luac */
#ifndef MAKE_LUAC
#include "lbaselib.c"
#if defined(LUA_COMPAT_BITLIB)
#include "lbitlib.c"
#endif
#include "lcorolib.c"
#include "ldblib.c"
#include "liolib.c"
#include "lmathlib.c"
#include "loadlib.c"
#include "loslib.c"
#include "lstrlib.c"
#include "ltablib.c"
#include "lutf8lib.c"
#include "linit.c"
#endif

/* lua */
#ifdef MAKE_LUA
#include "lua.c"
#endif

/* luac */
#ifdef MAKE_LUAC
#include "luac.c"
#endif
