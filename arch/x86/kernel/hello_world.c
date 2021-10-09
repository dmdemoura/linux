// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE1(hello_world, char*, msg)
{
	printk("Hello World syscall says: %s\n", msg);
	return 1;
}
