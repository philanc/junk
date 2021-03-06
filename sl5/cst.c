

// a temp, crude tool to explore constants, types and struct sizes
// on various architectures

// next is added to get  POLLRDHUP
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <linux/limits.h>	// PATH_MAX
#include <sys/stat.h>	// stat
#include <sys/types.h>	// getpid
#include <unistd.h>	// getpid, stat
#include <dirent.h>	// dir...
#include <termios.h>	// termios
#include <sys/ioctl.h>	// TCGETS, netif
#include <fcntl.h>	// open flags
#include <poll.h>	// poll
#include <linux/dm-ioctl.h>	// dm ioctl
#include <linux/loop.h>	// loop ioctl
#include <linux/fb.h>	// framebuffer
#include <sys/mount.h>	// BLKGETSIZE64
#include <sys/socket.h>	// socket..
#include <sys/un.h>	// AF_UNIX socket
#include <sys/wait.h>	// waitpid
#include <time.h>	// clock_gettime, clock_getres

// #include <sys/ioctl.h>  // for network interfaces (already incl)
#include <net/if.h>	// for network interfaces (netif)

#define dispint(x)	printf(#x " = %d\n", x);
#define dispintx(x)	printf(#x " = 0x%08x\n", x);
#define displongx(x)	printf(#x " = 0x%016lx\n", x);
#define dispsize(x)	printf("sizeof " #x " = %d\n", sizeof(x));

void main() {
	printf("---\n");
	char *p;
	dispsize((char *)p)
	dispsize(int)
	dispsize(long)
	dispsize(long long)
	dispsize(size_t)
	dispsize(pid_t)

	// stat
	dispsize(off_t)
	dispsize(uid_t)
	dispsize(mode_t)
	dispsize(nlink_t)
	dispsize(ino_t)
	dispsize(dev_t)
	dispsize(blksize_t)
	dispsize(blkcnt_t)
	//~ dispsize(__time_t)
	dispsize(time_t)
	dispsize(struct timespec)
	dispsize(struct timeval)
	dispsize(struct stat)
	dispintx(S_IFMT)  // mask for file type in mode
	dispintx(S_IFSOCK)
	dispintx(S_IFLNK)
	dispintx(S_IFREG)
	dispintx(S_IFBLK)
	dispintx(S_IFDIR)
	dispintx(S_IFCHR)
	dispintx(S_IFIFO)

	// path, dirs
	dispint(PATH_MAX)
	dispsize(struct dirent)

	// termios
	dispsize(struct termios)
	
	dispintx(~(BRKINT | ICRNL | INPCK | ISTRIP | IXON))
	dispintx(~(OPOST))
	dispintx(CS8)
	dispintx(~(ECHO | ICANON | IEXTEN | ISIG))
	dispint(VMIN)
	dispint(VTIME)
	dispint(TCSAFLUSH)
	struct termios tos;
	dispint((char*)&(tos.c_line) - (char*)&tos)
	dispint((char*)&(tos.c_cc) - (char*)&tos)
	dispint((char*)&(tos.c_cc[VTIME]) - (char*)&tos)
	dispsize(tos.c_cc)
	
	// ioctl
	///f/p3/git/tmp/musl-1.1.18/include/bits/ioctl.h
	dispintx(TCGETS) // 0x5401 
	dispintx(TCSETS) // 0x5402	
	
	// poll
	dispsize(struct pollfd)
	
	//open
	dispintx(O_RDONLY)
	dispintx(O_WRONLY)
	dispintx(O_RDWR)
	dispintx(O_CREAT)
	dispintx(O_DIRECTORY)
	dispintx(O_TRUNC)
	dispintx(O_APPEND)
	dispintx(O_CLOEXEC)
	//~ dispintx(O_TMPFILE)	// defined in /asm-generic/fcntl.h
	dispintx(020000000)	// O_TMPFILE (octal) in musl: 020200000
	dispintx(020200000)	//  ie O_TMPFILE | O_DIRECTORY  ?!?
	dispintx(O_EXCL)
	dispintx(O_NONBLOCK)
	dispintx(F_GETFD)
	dispintx(F_SETFD)
	dispintx(F_GETFL)
	dispintx(F_SETFL)
	//~ dispintx()
	
	// dm
	printf("---dm-ioctl\n");
	dispint(DM_VERSION_MAJOR)
	dispint(DM_VERSION_MINOR)
	dispintx(DM_VERSION)
	dispintx(DM_DEV_CREATE)
	dispintx(DM_DEV_SUSPEND)
	dispintx(DM_DEV_REMOVE)
	dispintx(DM_DEV_STATUS)
	dispintx(DM_TABLE_LOAD)
	dispintx(DM_TABLE_STATUS)
	dispintx(DM_LIST_DEVICES)
	dispsize(struct dm_ioctl)
	dispsize(struct dm_target_spec)
	struct dm_ioctl dmi;
	dispsize(dmi.name)
	dispsize(dmi.uuid)
	dispsize(struct dm_target_spec)
	dispintx(BLKGETSIZE64)
	dispintx(DM_MAX_TYPE_NAME)
	dispint((char*)&(dmi.name) - (char*)&dmi)
	
	// loop
	printf("---linux/loop.h\n");
	
	dispsize(struct loop_info64)
	struct loop_info64 li;
	dispsize(li.lo_device)
	dispsize(li.lo_inode)
	dispint(LO_NAME_SIZE)
	dispint(LO_KEY_SIZE)
	
	// sockets
	dispsize(struct sockaddr)
	dispsize(struct sockaddr_un)
	//~ dispsize(struct sockaddr_in)
	//~ dispsize(struct sockaddr_in6)
	dispsize(struct sockaddr_storage)
	dispintx(AF_UNIX)
	dispintx(AF_LOCAL)
	dispintx(AF_INET)
	dispintx(AF_INET6)
	dispintx(SOCK_STREAM)
	dispintx(SOCK_DGRAM)
	dispintx(SOCK_SEQPACKET)
	dispintx(SOCK_NONBLOCK)
	dispintx(SOCK_CLOEXEC)
	dispintx(SOL_SOCKET)
	dispintx(SO_KEEPALIVE)
	dispintx(SO_REUSEADDR)
	dispintx(MSG_DONTWAIT)
	//~ dispintx()
	
	struct pollfd pfd;
	pfd.fd=6; pfd.events=2; pfd.revents=3; 
	//~ dispsize(pfd.fd)
	//~ dispsize(pfd.events)
	//~ dispsize(pfd.revents)
	long pfdl = * ((long *) &pfd);
	displongx(pfdl)
	dispintx(POLLIN)
	dispintx(POLLOUT)
	dispintx(POLLHUP)
	dispintx(POLLRDHUP) // unknown without defined  _GNU_SOURCE
	dispintx(POLLERR)
	dispintx(POLLNVAL)

	dispintx(FIONBIO)
	
	// waitpid
	dispintx(WNOHANG)
	
	
	// FRAMEBUFFER
	
	dispintx(FBIOGET_VSCREENINFO)
	dispintx(FBIOGET_FSCREENINFO)
	dispintx(FBIOGETCMAP)
	dispintx(FB_VISUAL_TRUECOLOR)
	dispintx(FB_VISUAL_DIRECTCOLOR)
	dispintx(FB_VISUAL_PSEUDOCOLOR)
	dispintx(FB_VISUAL_STATIC_PSEUDOCOLOR)
	//~ dispintx()
	//~ dispintx()
	dispsize(struct fb_fix_screeninfo)
	dispsize(struct fb_var_screeninfo)
	dispsize(struct fb_cmap)
	dispsize(struct fb_bitfield)
	//~ dispsize()
	struct fb_fix_screeninfo finfo;
	struct fb_var_screeninfo vinfo;
	dispint((char*)&vinfo.red - (char*)&vinfo)
	dispint((char*)&vinfo.red.length - (char*)&vinfo)
	dispint((char*)&vinfo.green.length - (char*)&vinfo)
	dispint((char*)&vinfo.blue.length - (char*)&vinfo)
	dispint((char*)&finfo.smem_len - (char*)&finfo)
	//~ dispint((char*)&finfo.ywrapstep - (char*)&finfo)
	dispint((char*)&finfo.line_length - (char*)&finfo)
	
	// netif
	dispint(IFNAMSIZ)
	dispintx(SIOCGIFADDR)
	dispintx(SIOCSIFADDR)
	dispsize(struct ifreq)
	struct ifreq ifr;
	dispsize(ifr.ifr_addr)
	dispsize(ifr.ifr_map)
	dispint((char*)&ifr.ifr_ifindex - (char*)&ifr)
	
	// clock_gettime, ...
	dispintx(CLOCK_REALTIME)
	dispintx(CLOCK_MONOTONIC)
	dispintx(CLOCK_MONOTONIC_RAW)
	
	
	printf("---\n");
}





