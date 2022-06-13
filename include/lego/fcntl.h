/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_FCNTL_H_
#define _LEGO_FCNTL_H_

/* fcntl flags */
#define O_ACCMODE	00000003
#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#define O_CREAT		00000100	/* not fcntl */
#define O_EXCL		00000200	/* not fcntl */
#define O_NOCTTY	00000400	/* not fcntl */
#define O_TRUNC		00001000	/* not fcntl */
#define O_APPEND	00002000
#define O_NONBLOCK	00004000
#define O_DSYNC		00010000	/* used to be O_SYNC, see below */
#define FASYNC		00020000	/* fcntl, for BSD compatibility */
#define O_DIRECT	00040000	/* direct disk access hint */
#define O_LARGEFILE	00100000
#define O_DIRECTORY	00200000	/* must be a directory */
#define O_NOFOLLOW	00400000	/* don't follow links */
#define O_NOATIME	01000000
#define O_CLOEXEC	02000000	/* set close_on_exec */
#define O_NDELAY	O_NONBLOCK
#define AT_FDCWD	-100    	/* Special value used to indicate
                                           openat should use the current
                                           working directory. */

#define F_DUPFD		0	/* dup */
#define F_GETFD		1	/* get close_on_exec */
#define F_SETFD		2	/* set/clear close_on_exec */
#define F_GETFL		3	/* get file->f_flags */
#define F_SETFL		4	/* set file->f_flags */
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7
#define F_SETOWN	8	/* for sockets. */
#define F_GETOWN	9	/* for sockets. */
#define F_SETSIG	10	/* for sockets. */
#define F_GETSIG	11	/* for sockets. */
#define F_SETOWN_EX	15
#define F_GETOWN_EX	16
#define F_GETOWNER_UIDS	17

#define F_LINUX_SPECIFIC_BASE	1024
#define F_SETLEASE	(F_LINUX_SPECIFIC_BASE + 0)
#define F_GETLEASE	(F_LINUX_SPECIFIC_BASE + 1)
#define F_NOTIFY	(F_LINUX_SPECIFIC_BASE + 2)
#define F_DUPFD_CLOEXEC	(F_LINUX_SPECIFIC_BASE + 6)
#define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#define F_GETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 8)

/* for F_[GET|SET]FL */
#define FD_CLOEXEC	1	/* actually anything with low bit set goes */

#define AT_SYMLINK_NOFOLLOW	0x100   /* Do not follow symbolic links.  */
#define AT_REMOVEDIR		0x200   /* Remove directory instead of
                                           unlinking file.  */

#endif /* _LEGO_FCNTL_H_ */
