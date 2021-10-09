// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/syscalls.h>

/*
 * change the user struct in a credentials set to match the new UID
 */
static int set_user(struct cred *new)
{
	struct user_struct *new_user;

	new_user = alloc_uid(new->uid);
	if (!new_user)
		return -EAGAIN;

	/*
	 * We don't fail in case of NPROC limit excess here because too many
	 * poorly written programs don't check set*uid() return code, assuming
	 * it never fails if called by root.  We may still enforce NPROC limit
	 * for programs doing set*uid()+execve() by harmlessly deferring the
	 * failure to the execve() stage.
	 */
	if (is_ucounts_overlimit(new->ucounts, UCOUNT_RLIMIT_NPROC, rlimit(RLIMIT_NPROC)) &&
			new_user != INIT_USER)
		current->flags |= PF_NPROC_EXCEEDED;
	else
		current->flags &= ~PF_NPROC_EXCEEDED;

	free_uid(new->user);
	new->user = new_user;
	return 0;
}

long __sys_bad_setuid(uid_t uid)
{
	struct user_namespace *ns = current_user_ns();
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kuid;

	printk("Bad setuid called! Will try to set uid to %d.", uid);

	kuid = make_kuid(ns, uid);
	if (!uid_valid(kuid))
		return -EINVAL;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	retval = set_user(new);
	if (retval < 0)
		goto error;

	new->fsuid = new->euid = kuid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_ID);
	if (retval < 0)
		goto error;

	retval = set_cred_ucounts(new);
	if (retval < 0)
		goto error;

	printk("Bad setuid: Setting uid to %d.", uid);

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

SYSCALL_DEFINE1(bad_setuid, uid_t, uid)
{
	return __sys_bad_setuid(uid);
}
