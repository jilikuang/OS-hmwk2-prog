#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

struct prinfo {
	pid_t parent_pid;		/* process id of parent */
	pid_t pid;			/* process id */
	pid_t first_child_pid;  	/* pid of youngest child */
	pid_t next_sibling_pid;  	/* pid of older sibling */
	long state;			/* current state of process */
	long uid;			/* user id of process owner */
	char comm[64];			/* name of program executed */
};

#define __NR_ptree 223

int main(int argc, char **argv) {

	long ret;
	struct prinfo* inf = (struct prinfo*) malloc (sizeof (struct prinfo) * 1000);
	struct prinfo* p_info;
	int nr = 1000, i;
	ret = syscall (__NR_ptree, inf, &nr);
	printf ("nr = %d\n", nr);	
	if (ret == 0) {
		for (i=0; i<nr; ++i) {

			p_info = &(inf[i]);
			
			printf ("%s,%d,%d\n", 
				p_info->comm, 
				p_info->pid, 
				p_info->parent_pid);
			/*
			printf ("%s,%d,%ld,%d,%d,%d,%ld\n", 
				p_info->comm, 
				p_info->pid, 
				p_info->state,
				p_info->parent_pid, 
				p_info->first_child_pid, 
				p_info->next_sibling_pid, 
				p_info->uid);
			*/
		}	
	}

	printf ("ret = %x\n", (int)ret);
	return 0;
}
