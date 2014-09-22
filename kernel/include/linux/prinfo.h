#ifndef __PRINFO_H__
#define __PRINFO_H__

#include <linux/types.h>

struct prinfo {
	pid_t parent_pid;		/* process id of parent */
	pid_t pid;			/* process id */
	pid_t first_child_pid;		/* pid of youngest child */
	pid_t next_sibling_pid;		/* pid of older sibling */
	long state;			/* current state of process */
	long uid;			/* user id of process owner */
	char comm[64];			/* name of program executed */
};

struct pr_task_node {

	/* a pointer to the 'real' task info */
	struct task_struct *mp_task;

	/* this node canbe in several lists -> need list head for every list */
	struct list_head m_visited;
	struct list_head m_to_pop;
	struct list_head m_output;
};

extern struct task_struct init;
#if 1
	#define PRINTK(...) 
#else
	#define PRINTK printk
#endif
/* Test function to print the prinfo */
#endif
