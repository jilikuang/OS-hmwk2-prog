/* Implementation of prinfo system call */

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/utsname.h>
#include <linux/mman.h>
#include <linux/reboot.h>
#include <linux/prctl.h>
#include <linux/highuid.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/perf_event.h>
#include <linux/resource.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/workqueue.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/posix-timers.h>
#include <linux/security.h>
#include <linux/dcookies.h>
#include <linux/suspend.h>
#include <linux/tty.h>
#include <linux/signal.h>
#include <linux/cn_proc.h>
#include <linux/getcpu.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/seccomp.h>
#include <linux/cpu.h>
#include <linux/personality.h>
#include <linux/ptrace.h>
#include <linux/fs_struct.h>
#include <linux/gfp.h>
#include <linux/syscore_ops.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <linux/mempolicy.h>

#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/user_namespace.h>

#include <linux/kmsg_dump.h>

/* Move somewhere else to avoid recompiling? */
#include <generated/utsrelease.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

#include <linux/prinfo.h>  /* @lfred */

/* Fill in prinfo with given task struct */
static int fill_in_prinfo(struct prinfo *info, struct task_struct *p)
{
	int retval = 0;

	info->parent_pid = p->parent->pid;
	info->pid = p->pid;

	if (!list_empty(&(p->children)))
		info->first_child_pid = list_first_entry(
				&p->children,
				struct task_struct,
				sibling)->pid; /* Jili: Data to confirm */
	else
		info->first_child_pid = 0;

	if (!list_empty(&(p->sibling))) {

		if (list_first_entry(
			&p->sibling,
			struct task_struct,
			children) == p->parent)
				info->next_sibling_pid = 0;
		else
			info->next_sibling_pid = list_first_entry(
				&p->sibling,
				struct task_struct,
				sibling)->pid;/* Jili: Data to confirm */
	} else
		info->next_sibling_pid = 0;

	info->state = p->state;

	if (p->cred != NULL)
		info->uid = p->cred->uid;
	else
		info->uid = 0;

	strncpy(info->comm, p->comm, 64);
	info->comm[63] = 0;

	return retval;
}

/* @lfred: the function is used to retrieve the root node */
static struct task_struct *find_root_proc(void)
{
	return &init_task;
}

static struct task_struct *find_unvisited_child(
	struct list_head *p_children,
	struct list_head *p_visited) {

	struct task_struct *child;
	struct pr_task_node *vst;

	int in_the_visited_list = 0;

	list_for_each_entry(child, p_children, sibling) {

		in_the_visited_list = 0;

		PRINTK("\t[TREE] Testing unvisited child: %d\n", child->pid);

		list_for_each_entry_reverse(vst, p_visited, m_visited) {
			if (child == vst->mp_task) {
				in_the_visited_list = 1;
				break;
			}
		}

		if (in_the_visited_list == 0) {
			PRINTK("[TREE] Fnd unvisited chd: %d\n", child->pid);
			return child;
		}
	}

	return NULL;
}

/* @lfred */
SYSCALL_DEFINE2(ptree,
		struct prinfo*, buf,
		int*, nr)
{
	int retval = 0;

	struct task_struct *p_cur = NULL;
	struct task_struct *p_unvisted_child = NULL;
	struct pr_task_node *new_node;

	int counter = 1;

	/* kernel buffer */
	struct prinfo *p_kBuf = NULL;
	int kNr = 0;
	int cnt = 0;

	/* initialize 3 queues used in the DFS algo */
	LIST_HEAD(to_pop_head);		/* a temp storage */
	LIST_HEAD(visited_head);	/* to remember where we've been */

	/* Fast access to the Q head */
	struct list_head *p_to_pop  = &to_pop_head;
	struct list_head *p_visited = &visited_head;

	/* Check pointer validity */
	if (!buf || !nr)
		return -EFAULT;

	retval = copy_from_user(&kNr, nr, sizeof(int));

	/* retval should be 0. > 0 means some bytes are not copied */
	if (retval > 0)
		return -EFAULT;

	if (kNr == 0)
		return -EFAULT;

	if (!access_ok(VERIFY_WRITE, buf, kNr * sizeof(struct prinfo)))
		return -EFAULT;

	p_kBuf = kmalloc_array(kNr, sizeof(struct prinfo), GFP_ATOMIC);
	if (p_kBuf == NULL)
		return -ENOMEM;

	new_node = kmalloc(sizeof(struct pr_task_node), GFP_ATOMIC);
	if (new_node == NULL) {
		kfree(p_kBuf);
		return -ENOMEM;
	}

	retval = 0;

	/* lock the list access --> be sure to release */
	/* After this section, should not directly return */
	/* Need to unlock and free memory */
	read_lock(&tasklist_lock);

	/* step 1: find the root of the task tree */
	p_cur = find_root_proc();

	INIT_LIST_HEAD(&new_node->m_visited);
	INIT_LIST_HEAD(&new_node->m_to_pop);

	/* add init task to visited, to_pop list, and output list */
	new_node->mp_task = p_cur;
	list_add(p_to_pop, &new_node->m_to_pop);
	list_add(p_visited, &new_node->m_visited);
	fill_in_prinfo(&(p_kBuf[cnt++]), p_cur);

	/* Don't need to continue if buffer is not enough */
	if (cnt == kNr)
		goto __algo_end;

	while (!list_empty(p_to_pop)) {

		/* a pointer to the child 'list_head' */
		struct list_head *p_children = &(p_cur->children);

		if (list_empty(p_children)) {

			/* get the tail of the output to_pop queue */
			struct pr_task_node *queue_tail =
				list_entry(
					p_to_pop->prev,
					struct pr_task_node,
					m_to_pop);

			PRINTK("[TREE] output: case 1 - %d\n", p_cur->pid);
			list_del(&(queue_tail->m_to_pop));

			if (list_empty(p_to_pop)) {
				PRINTK("[TREE] WTF !!!\n");
				break;
			}

			/* next should be the top of to-pop stack */
			p_cur = list_entry(
					p_to_pop->prev,
					struct pr_task_node,
					m_to_pop)->mp_task;

			continue;
		}

		p_unvisted_child = find_unvisited_child(p_children, p_visited);

		/* if current process has unvisited child */
		if (p_unvisted_child != NULL) {

			new_node = kmalloc(sizeof(struct pr_task_node),
					GFP_ATOMIC);

			if (new_node == NULL) {
				PRINTK("[TREE] memory allocation failure\n");
				retval = -ENOMEM;
				goto __algo_end;
			}

			p_cur = new_node->mp_task = p_unvisted_child;
			INIT_LIST_HEAD(&new_node->m_visited);
			INIT_LIST_HEAD(&new_node->m_to_pop);

			/* added to the visited and pop list */
			counter++;
			list_add_tail(&new_node->m_visited, p_visited);
			list_add_tail(&new_node->m_to_pop, p_to_pop);
			fill_in_prinfo(&(p_kBuf[cnt++]), p_cur);

			/* Don't need to continue if buffer is not enough */
			if (cnt == kNr)
				goto __algo_end;
		}
		/* No more children to work-on */
		else {
			/* get the tail of the output to_pop queue */
			struct pr_task_node *stack_top =
				list_entry(
					p_to_pop->prev,
					struct pr_task_node,
					m_to_pop);

			list_del(&(stack_top->m_to_pop));

			/* traverse stack-top */
			if (!list_empty(p_to_pop)) {
				p_cur = list_entry(
						p_to_pop->prev,
						struct pr_task_node,
						m_to_pop)->mp_task;
			} else {
				PRINTK("[TREE] Nothing left, terminated\n");
				break;
			}
		}
	}

__algo_end:
	read_unlock(&tasklist_lock);

	/* clean up stage 1 - free visited list */
	while (!list_empty(p_visited)) {
		struct pr_task_node *pos = NULL;
		struct list_head *p_list = NULL;

		p_list = p_visited->next;
		pos = list_entry(p_list, struct pr_task_node, m_visited);
		list_del(p_list);
		kfree(pos);
	}

	/* If come here for abortion, exit directly */
	if (retval < 0)
		goto __ptree_exit;

	PRINTK("[TREE] Total tasks: %d, usr buffer size: %d\n", counter, kNr);

	cnt = (cnt > kNr) ? kNr : cnt;
	if (copy_to_user(buf, p_kBuf, cnt * sizeof(struct prinfo)) != 0) {
		PRINTK("[TREE] copy to user failed - 1\n");
		retval = -EFAULT;
		goto __ptree_exit;
	}

	if (copy_to_user(nr, &counter, sizeof(int)) != 0) {
		PRINTK("[TREE] copy_to_user failed - 2\n");
		retval = -EFAULT;
	}

__ptree_exit:

	/* clean up stage 2 */
	kfree(p_kBuf);

	return retval;
}

