#ifndef __PRINFO_H__
#define __PRINFO_H__

#include <linux/types.h>

struct prinfo {
	pid_t parent_pid;		/* process id of parent */
	pid_t pid;			/* process id */
	pid_t first_child_pid;  	/* pid of youngest child */
	pid_t next_sibling_pid;  	/* pid of older sibling */
	long state;			/* current state of process */
	long uid;			/* user id of process owner */
	char comm[64];			/* name of program executed */
};

/* Jili */
/* Define prinfo info list to restore DFS-traversed processes */
struct prlist_node {
	struct prinfo info;
	struct list_head list;
};

/* Test function to print the prinfo */
#endif
