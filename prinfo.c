#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

struct prinfo {
	pid_t parent_pid;		/* process id of parent */
	pid_t pid;			/* process id */
	pid_t first_child_pid;		/* pid of youngest child */
	pid_t next_sibling_pid;		/* pid of older sibling */
	long state;			/* current state of process */
	long uid;			/* user id of process owner */
	char comm[64];			/* name of program executed */
};

#define __NR_ptree 223

static int *gp_stack;
static int g_stack_idx;
static int g_climit = 100;

void init_stack(void)
{
	gp_stack = (int *) malloc(sizeof(int) * g_climit);
	g_stack_idx = 0;
}

void deinit_stack(void)
{
	free(gp_stack);
	g_stack_idx = 0;
}

void push(int x)
{
	if (g_stack_idx == g_climit - 1) {
		g_climit += 100;
		gp_stack = realloc(gp_stack, g_climit);
	}

	if (gp_stack != NULL) {
		gp_stack[g_stack_idx++] = x;
	} else {
		printf("Insufficient memory.\n");
		exit(0);
	}
}

int pop(void)
{
	int r = -1;

	if (g_stack_idx > 0)
		r = gp_stack[--g_stack_idx];
	return r;
}

int peep(void)
{
	if (g_stack_idx > 0)
		return gp_stack[g_stack_idx - 1];

	return -1;
}

int num_of_stack(void)
{
	return g_stack_idx;
}

void print_tabs(int x)
{
	int i = 0;

	for (i = 0; i < x; ++i)
		printf("\t");
}

int test_function(int n)
{
	long ret;
	struct prinfo *inf =
		(struct prinfo *) malloc(sizeof(struct prinfo) * n);
	struct prinfo *p_info;
	int nr = n, i, tmp;

	if (inf == NULL)
		return -2;

	ret = syscall(__NR_ptree, inf, &nr);
	/* fprintf(stderr, "nr = %d\n", nr); */

	if (ret != 0) {
		printf("System call error: %d\n", (int)ret);
		free(inf);
		return 0;
	}

	if (nr == n) {
		free(inf);
		return -1;
	}

	init_stack();

	for (i = 0; i < nr; ++i) {

		p_info = &(inf[i]);

		int cur_top = peep();

		if (cur_top == -1) {
			push(p_info->pid);
		} else if (cur_top == p_info->parent_pid) {
			print_tabs(num_of_stack());
			push(p_info->pid);
		} else {
			while ((tmp = pop()) != -1) {
				if (tmp == p_info->parent_pid) {
					push(tmp);
					print_tabs(num_of_stack());
					push(p_info->pid);
					break;
				}
			}
		}

		printf("%s,%d,%ld,%d,%d,%d,%ld\n",
			p_info->comm,
			p_info->pid,
			p_info->state,
			p_info->parent_pid,
			p_info->first_child_pid,
			p_info->next_sibling_pid,
			p_info->uid);
	}

	deinit_stack();
	return nr;
}

int main(void)
{
	#if 0
	int j = 0;
	int i = 0;

	for (j = 0; j < 10; j++) {

		fprintf(stderr, "Round: %d\n", j);

		for (i = 0; i < 150; i++)
			test_function(i);
	}
	#else
	int param = 20;

	while (test_function(param) == -1)
		param += 20;

	#endif
	return 0;
}
