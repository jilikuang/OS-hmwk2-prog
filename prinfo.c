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

#define __NR_ptree 378

int main(int argc, char **argv) {

	long ret;
	struct prinfo* inf = NULL;
	int y;
	ret = syscall (__NR_ptree, inf, &y);
	printf ("ret = %d\n", (int)ret);
	return 0;
}
