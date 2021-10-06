// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE1(hello_world, char*, msg)
{
	printk("%s", msg);
	return 1;
}
