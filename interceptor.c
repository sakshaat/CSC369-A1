#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/unistd.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include "interceptor.h"


MODULE_DESCRIPTION("This module hijacks system calls.");
MODULE_AUTHOR("Sakshaat Choyikandi");
MODULE_LICENSE("GPL");


//----- System Call Table Stuff ------------------------------------
/* Symbol that allows access to the kernel system call table */
extern void* sys_call_table[];

/* The sys_call_table is read-only => must make it RW before replacing a syscall */
void set_addr_rw(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

/* Restores the sys_call_table as read-only */
void set_addr_ro(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;

}
//-------------------------------------------------------------


//----- Data structures and bookkeeping -----------------------
/**
 * This block contains the data structures needed for keeping track of
 * intercepted system calls (including their original calls), pid monitoring
 * synchronization on shared data, etc.
 * It's highly unlikely that you will need any globals other than these.
 */

/* List structure - each intercepted syscall may have a list of monitored pids */
struct pid_list {
    pid_t pid;
    struct list_head list;
};


/* Store info about intercepted/replaced system calls */
typedef struct {

    /* Original system call */
    asmlinkage long (*f)(struct pt_regs);

    /* Status: 1=intercepted, 0=not intercepted */
    int intercepted;

    /* Are any PIDs being monitored for this syscall? */
    int monitored;
    /* List of monitored PIDs */
    int listcount;
    struct list_head my_list;
} mytable;

/* An entry for each system call in this "metadata" table */
mytable table[NR_syscalls+1];

/* Access to the system call table and your metadata table must be synchronized */
spinlock_t my_table_lock = SPIN_LOCK_UNLOCKED;
spinlock_t sys_call_table_lock = SPIN_LOCK_UNLOCKED;


//-------------------------------------------------------------


//----------LIST OPERATIONS------------------------------------
/**
 * These operations are meant for manipulating the list of pids
 * Nothing to do here, but please make sure to read over these functions
 * to understand their purpose, as you will need to use them!
 */

/**
 * Add a pid to a syscall's list of monitored pids.
 * Returns -ENOMEM if the operation is unsuccessful.
 */
static int add_pid_sysc(pid_t pid, int sysc)
{
    struct pid_list *ple=(struct pid_list*)kmalloc(sizeof(struct pid_list), GFP_KERNEL);

    if (!ple)
        return -ENOMEM;

    INIT_LIST_HEAD(&ple->list);
    ple->pid=pid;

    list_add(&ple->list, &(table[sysc].my_list));
    table[sysc].listcount++;

    return 0;
}

/**
 * Remove a pid from a system call's list of monitored pids.
 * Returns -EINVAL if no such pid was found in the list.
 */
static int del_pid_sysc(pid_t pid, int sysc)
{
    struct list_head *i;
    struct pid_list *ple;

    list_for_each(i, &(table[sysc].my_list)) {

        ple=list_entry(i, struct pid_list, list);
        if(ple->pid == pid) {

            list_del(i);
            kfree(ple);

            table[sysc].listcount--;
            /* If there are no more pids in sysc's list of pids, then
             * stop the monitoring only if it's not for all pids (monitored=2) */
            if(table[sysc].listcount == 0 && table[sysc].monitored == 1) {
                table[sysc].monitored = 0;
            }

            return 0;
        }
    }

    return -EINVAL;
}

/**
 * Remove a pid from all the lists of monitored pids (for all intercepted syscalls).
 * Returns -1 if this process is not being monitored in any list.
 */
static int del_pid(pid_t pid)
{
    struct list_head *i, *n;
    struct pid_list *ple;
    int ispid = 0, s = 0;

    for(s = 1; s < NR_syscalls; s++) {

        list_for_each_safe(i, n, &(table[s].my_list)) {

            ple=list_entry(i, struct pid_list, list);
            if(ple->pid == pid) {

                list_del(i);
                ispid = 1;
                kfree(ple);

                table[s].listcount--;
                /* If there are no more pids in sysc's list of pids, then
                 * stop the monitoring only if it's not for all pids (monitored=2) */
                if(table[s].listcount == 0 && table[s].monitored == 1) {
                    table[s].monitored = 0;
                }
            }
        }
    }

    if (ispid) return 0;
    return -1;
}

/**
 * Clear the list of monitored pids for a specific syscall.
 */
static void destroy_list(int sysc) {

    struct list_head *i, *n;
    struct pid_list *ple;

    list_for_each_safe(i, n, &(table[sysc].my_list)) {

        ple=list_entry(i, struct pid_list, list);
        list_del(i);
        kfree(ple);
    }

    table[sysc].listcount = 0;
    table[sysc].monitored = 0;
}

/**
 * Check if two pids have the same owner - useful for checking if a pid
 * requested to be monitored is owned by the requesting process.
 * Remember that when requesting to start monitoring for a pid, only the
 * owner of that pid is allowed to request that.
 */
static int check_pids_same_owner(pid_t pid1, pid_t pid2) {

    struct task_struct *p1 = pid_task(find_vpid(pid1), PIDTYPE_PID);
    struct task_struct *p2 = pid_task(find_vpid(pid2), PIDTYPE_PID);
    if(p1->real_cred->uid != p2->real_cred->uid)
        return -EPERM;
    return 0;
}

/**
 * Check if a pid is already being monitored for a specific syscall.
 * Returns 1 if it already is, or 0 if pid is not in sysc's list.
 */
static int check_pid_monitored(int sysc, pid_t pid) {

    struct list_head *i;
    struct pid_list *ple;

    list_for_each(i, &(table[sysc].my_list)) {

        ple=list_entry(i, struct pid_list, list);
        if(ple->pid == pid)
            return 1;

    }
    return 0;
}
//----------------------------------------------------------------

//----- Intercepting exit_group ----------------------------------
/**
 * Since a process can exit without its owner specifically requesting
 * to stop monitoring it, we must intercept the exit_group system call

 * so that we can remove the exiting process's pid from *all* syscall lists.
 */

/**
 * Stores original exit_group function - after all, we must restore it
 * when our kernel module exits.
 */
void (*orig_exit_group)(int);

/**
 * Our custom exit_group system call.
 *
 * TODO: When a process exits, make sure to remove that pid from all lists.
 * The exiting process's PID can be retrieved using the current variable (current->pid).
 * Don't forget to call the original exit_group.
 *
 * Note: using printk in this function will potentially result in errors!
 *
 */
void my_exit_group(int status) {
    // Delete the current pid from all syscall monitoring lists.
    del_pid(current->pid);
    // Run the original exit group function.
    orig_exit_group(status);
}
//----------------------------------------------------------------



/**
 * This is the generic interceptor function.
 * It should just log a message and call the original syscall.
 *
 * TODO: Implement this function.
 * - Check first to see if the syscall is being monitored for the current->pid.
 * - Recall the convention for the "monitored" flag in the mytable struct:
 *     monitored=0 => not monitored
 *     monitored=1 => some pids are monitored, check the corresponding my_list
 *     monitored=2 => all pids are monitored for this syscall
 * - Use the log_message macro, to log the system call parameters!
 *     Remember that the parameters are passed in the pt_regs registers.
 *     The syscall parameters are found (in order) in the
 *     ax, bx, cx, dx, si, di, and bp registers (see the pt_regs struct).
 * - Don't forget to call the original system call, so we allow processes to proceed as normal.
 *
 */
asmlinkage long interceptor(struct pt_regs reg) {
    // Interception is dependent on the current value of 
    // the call's monitored variable.
    switch(table[reg.ax].monitored) {
        case 1:
            // Case where some pids are being monitored.
            if(check_pid_monitored(reg.ax, current->pid)){
                // Log a message if the entered pid is being monitored.
                 log_message(current->pid, reg.ax, reg.bx, reg.cx, reg.dx, reg.si, reg.di, reg.bp);
             }
            break;
        case 2:
            // Case where every pid is monitored (except the blacklisted pids)
            if(!check_pid_monitored(reg.ax, current->pid)) {
                // If pid is not in the blacklist, log a message.
                 log_message(current->pid, reg.ax, reg.bx, reg.cx, reg.dx, reg.si, reg.di, reg.bp);
             }
            break;
    }

    // Run the original function for the syscall.
    return table[reg.ax].f(reg);
}

asmlinkage int start_intercepting(int syscall, int pid) {
    // Check if the call is already being intercepted.
    if (table[syscall].intercepted == 1) {
        return -EBUSY;
    }

    // Store the original system call inside the 
    // table struct to be accessed later.
    // Get the my table lock;
    spin_lock(&my_table_lock);
    table[syscall].f = sys_call_table[syscall];
    // Modify the intercepted variable to show that it is being intercepted.
    table[syscall].intercepted = 1;
    // Release the lock.
    spin_unlock(&my_table_lock);

    // Get the sys_call table lock.
    spin_lock(&sys_call_table_lock);
    // Set the syscall table to read and write to make changes.
    set_addr_rw((unsigned long)sys_call_table);
    // Switch its sys_call entry with our interceptor function.
    sys_call_table[syscall] = interceptor;
    // Set the table back to read only.
    set_addr_ro((unsigned long)sys_call_table);
    spin_unlock(&sys_call_table_lock);

    return 0;
}
/** Helper function responsible for releasing the intercept command
*   from a syscall.
*/
asmlinkage int stop_intercepting(int syscall, int pid) {
    // Cannot deintercept a call that has not been intercepted yet.
    if(table[syscall].intercepted== 0) {
        return -EINVAL;
    }

    spin_lock(&sys_call_table_lock);
    // Set the table to read and write to make changes.
    set_addr_rw((unsigned long)sys_call_table);
    // Switch the sys table entry back to its original function.
    sys_call_table[syscall] = table[syscall].f;
    // Set the table back to read only.
    set_addr_ro((unsigned long)sys_call_table);
    spin_unlock(&sys_call_table_lock);

    spin_lock(&my_table_lock);
    // Deintercept the call and clear its monitored list.
    table[syscall].intercepted = 0;
    destroy_list(syscall);
    // give up the table lock
    spin_unlock(&my_table_lock);

    return 0;
}

/** Helper function responsible for stop monitoring commands
*   the intercept commands
*/
asmlinkage int stop_monitoring(int syscall, int pid) {
    int uid, result, monitored;
    uid = current_uid();
    result = 0;

    // lock the table
    spin_lock(&my_table_lock);

    // storing it in a variable to avoid multiple list accesses
    monitored = table[syscall].monitored;

    // cannot stop monitoring a process that is not
    // being monitored or intercepted
    if(monitored==0) {
        spin_unlock(&my_table_lock);
        return -EINVAL;
    }

    // If pid is 0, every pid is de-monitored.
    if(pid == 0) {
        // make changes in the list, lock first
        // delete all monitored pids and initialize the new list head
        destroy_list(syscall);
        INIT_LIST_HEAD(&table[syscall].my_list);

    } else {
        if (monitored == 2) {
            // special case
            // cannot monitor a process that is already monitored.
            if(check_pid_monitored(syscall, pid) == 1 ){
                spin_unlock(&my_table_lock);
                return -EINVAL;
            }
            // if all pids are being monitored
            // add the specified pid into our blacklist
            result = add_pid_sysc(pid, syscall);
        } else {
            // delete the pid from the list of monitored pids
            result = del_pid_sysc(pid, syscall);
            // if the list is empty, change monitored status to 0
            if(table[syscall].listcount == 0) {
                table[syscall].monitored = 0;
            }
        }
    }

    // unlock the table
    spin_unlock(&my_table_lock);

    // return the result of the execution
    return result;
}

/** Helper function responsible for starting the monitoring command
*   from a syscall.
*/
asmlinkage int start_monitoring(int syscall, int pid) {
    int result, monitored;
    // Initializing the return variable.
    result = 0;

    // If pid is 0, every pid should be monitored.
    if(pid == 0) {
        spin_lock(&my_table_lock);
        // Destroy the existing list for the syscall
        // in order to use it as a blacklist for the bonus question.
        destroy_list(syscall);
        INIT_LIST_HEAD(&(table[syscall].my_list));
        // Change the status of the monitored variable.
        table[syscall].monitored = 2;
        spin_unlock(&my_table_lock);
    } else {
        // Need to make sure nobody else changes it.
        monitored = table[syscall].monitored;
        if (monitored == 2) {
            // Special case when every pid is monitored.
            if (check_pid_monitored(syscall, pid) == 1) {
                spin_lock(&my_table_lock);
                // Retrieve the result of del_pid_sysc.
                result = del_pid_sysc(pid, syscall);
                spin_unlock(&my_table_lock);
            } else {
                // It is already being monitored.
                return -EBUSY;
            }
        } else {
            // Can't monitor a pid that is already being monitored.
            if(check_pid_monitored(syscall, pid)==1) {
                return -EBUSY;
            }

            // Add the pid to the list and change the monitored attr to 1.
            spin_lock(&my_table_lock);
            result = add_pid_sysc(pid, syscall);
            // If there is a memory error then do not change
            // the value of monitored.
            if(result != -ENOMEM) {
                table[syscall].monitored = 1;
            }
            spin_unlock(&my_table_lock);
        }
    }

    // return the result of the execution
    return result;
}

/* Helper function resposible for doing permission checks and delagating
* the intercepting task to the responsible helper function.
*/
asmlinkage int intercept_requests(int cmd, int syscall, int pid) {
    int uid, result;
    uid = current_uid();
    // Initializing result to avoid issues.
    result = 0;

    // Check if the caller has root permissions or not
    if(uid != 0) {
        return -EPERM;
    }

    // Find out which intercept command the user has inputted and
    // enter the corresponding helper function
    if (cmd == REQUEST_SYSCALL_INTERCEPT) {
         result = start_intercepting(syscall, pid);
    } else if (cmd == REQUEST_SYSCALL_RELEASE) {
        result = stop_intercepting(syscall, pid);
    }

    // return the result of the execution
    return result;
}


/* Helper function resposible for doing validity checks and delagating
* the monitoring task to the responsible helper function.
*/
asmlinkage int monitoring_requests(int cmd, int syscall, int pid) {
    int uid, result;
    uid = current_uid();
    result = 0;

    // Checking to see if the pid entered is valid.
    if( pid < 0 || pid_task(find_vpid(pid), PIDTYPE_PID) == NULL) {
        // if the pid is not 0 it is invalid.
        // we need this check because the second case of the
        // if statement returns null if pid == 0
        if(pid != 0) {
            return -EINVAL;
        }
    }

    // If the call has not yet been intercepted, return -EINVAL
    if(table[syscall].intercepted == 0) {
        return -EINVAL;
    }

    // Checks if the user is root, if not, check if they have the
    // required permissions.
    if(uid != 0) {
        if(pid == 0 || check_pids_same_owner(current->pid, pid) != 0) {
            return -EPERM;
        }
    }

    // Delagates the appropriate monitoring task to the helper function
    // responsible for it.
    if (cmd == REQUEST_START_MONITORING) {
        result = start_monitoring(syscall, pid);
    } else if (cmd == REQUEST_STOP_MONITORING) {
        result = stop_monitoring(syscall, pid);
    }

    // Return the result of the execution to the caller.
    return result;
}


/**
 * My system call - this function is called whenever a user issues a MY_CUSTOM_SYSCALL system call.
 * When that happens, the parameters for this system call indicate one of 4 actions/commands:
 *      - REQUEST_SYSCALL_INTERCEPT to intercept the 'syscall' argument
 *      - REQUEST_SYSCALL_RELEASE to de-intercept the 'syscall' argument
 *      - REQUEST_START_MONITORING to start monitoring for 'pid' whenever it issues 'syscall'
 *      - REQUEST_STOP_MONITORING to stop monitoring for 'pid'
 *      For the last two, if pid=0, that translates to "all pids".
 *
 * TODO: Implement this function, to handle all 4 commands correctly.
 *
 * - For each of the commands, check that the arguments are valid (-EINVAL):
 *   a) the syscall must be valid (not negative, not > NR_syscalls, and not MY_CUSTOM_SYSCALL itself)
 *   b) the pid must be valid for the last two commands. It cannot be a negative integer,
 *      and it must be an existing pid (except for the case when it's 0, indicating that we want
 *      to start/stop monitoring for "all pids").
 *      If a pid belongs to a valid process, then the following expression is non-NULL:
 *           pid_task(find_vpid(pid), PIDTYPE_PID)
 * - Check that the caller has the right permissions (-EPERM)
 *      For the first two commands, we must be root (see the current_uid() macro).
 *      For the last two commands, the following logic applies:
 *        - is the calling process root? if so, all is good, no doubts about permissions.
 *        - if not, then check if the 'pid' requested is owned by the calling process
 *        - also, if 'pid' is 0 and the calling process is not root, then access is denied
 *          (monitoring all pids is allowed only for root, obviously).
 *      To determine if two pids have the same owner, use the helper function provided above in this file.
 * - Check for correct context of commands (-EINVAL):
 *     a) Cannot de-intercept a system call that has not been intercepted yet.
 *     b) Cannot stop monitoring for a pid that is not being monitored, or if the
 *        system call has not been intercepted yet.
 * - Check for -EBUSY conditions:
 *     a) If intercepting a system call that is already intercepted.
 *     b) If monitoring a pid that is already being monitored.
 * - If a pid cannot be added to a monitored list, due to no memory being available,
 *   an -ENOMEM error code should be returned.
 *
 *   NOTE: The order of the checks may affect the tester, in case of several error conditions
 *   in the same system call, so please be careful!
 *
 * - Make sure to keep track of all the metadata on what is being intercepted and monitored.
 *   Use the helper functions provided above for dealing with list operations.
 *
 * - Whenever altering the sys_call_table, make sure to use the set_addr_rw/set_addr_ro functions
 *   to make the system call table writable, then set it back to read-only.
 *   For example: set_addr_rw((unsigned long)sys_call_table);
 *   Also, make sure to save the original system call (you'll need it for 'interceptor' to work correctly).
 *
 * - Make sure to use synchronization to ensure consistency of shared data structures.
 *   Use the calltable_spinlock and pidlist_spinlock to ensure mutual exclusion for accesses
 *   to the system call table and the lists of monitored pids. Be careful to unlock any spinlocks
 *   you might be holding, before you exit the function (including error cases!).
 */
asmlinkage long my_syscall(int cmd, int syscall, int pid) {
    // Checking the integrity of the arguments before anything else.
    if (syscall < 0 || syscall > NR_syscalls || syscall == MY_CUSTOM_SYSCALL) {
        return -EINVAL;
    }

    // Picks the appropriate helper function depending on the user request.
    if(cmd == REQUEST_SYSCALL_INTERCEPT || cmd == REQUEST_SYSCALL_RELEASE) {
        return intercept_requests(cmd, syscall, pid);
    } else {
        return monitoring_requests(cmd, syscall, pid);
    }
}

/** Saves the original custom system call.
 */
long (*orig_custom_syscall)(void);


/**
 * Module initialization.
 *
 * TODO: Make sure to:
 * - Hijack MY_CUSTOM_SYSCALL and save the original in orig_custom_syscall.
 * - Hijack the exit_group system call (__NR_exit_group) and save the original
 *   in orig_exit_group.
 * - Make sure to set the system call table to writable when making changes,
 *   then set it back to read only once done.
 * - Perform any necessary initializations for bookkeeping data structures.
 *   To initialize a list, use
 *        INIT_LIST_HEAD (&some_list);
 *   where some_list is a "struct list_head".
 * - Ensure synchronization as needed.
 */
static int init_function(void) {
    int i;

    // Saving the original syscalls to be used later
    orig_custom_syscall = sys_call_table[MY_CUSTOM_SYSCALL];
    orig_exit_group = sys_call_table[__NR_exit_group];

    spin_lock(&sys_call_table_lock);
    // To make changes to the syscall table 
    // we must change the sys call table to rw.
    set_addr_rw((unsigned long)sys_call_table);
    // switch our custom functions with the original functions in
    // the system call table.
    sys_call_table[MY_CUSTOM_SYSCALL] = my_syscall;
    sys_call_table[__NR_exit_group] = my_exit_group;
    // Set the table back to read only.
    set_addr_ro((unsigned long)sys_call_table);
    spin_unlock(&sys_call_table_lock);

    // Initializing all the data structures required for execution.
    spin_lock(&my_table_lock);
    i=0;
    
    while(i<NR_syscalls) {
        INIT_LIST_HEAD(&(table[i].my_list));
        table[i].intercepted = 0;
        table[i].monitored = 0;
        table[i].listcount = 0;
        i++;
    }

    spin_unlock(&my_table_lock);
    return 0;
}

/**
 * Module exits.
 *
 * TODO: Make sure to:
 * - Restore MY_CUSTOM_SYSCALL to the original syscall.
 * - Restore __NR_exit_group to its original syscall.
 * - Make sure to set the system call table to writable when making changes,
 *   then set it back to read only once done.
 * - Make sure to deintercept all syscalls, and cleanup all pid lists.
 * - Ensure synchronization, if needed.
 */
static void exit_function(void) {
    int i;

    spin_lock(&sys_call_table_lock);
    // Setting sys call table values to their original values
    // Have to make the sys call table rw first.
    set_addr_rw((unsigned long)sys_call_table);
    sys_call_table[MY_CUSTOM_SYSCALL] = orig_custom_syscall;
    sys_call_table[__NR_exit_group] = orig_exit_group;
    // Set the table back to read only.

    // deintercept all system calls and clean up pid lists.
    i = 0;
    while (i < NR_syscalls) {
        if(table[i].intercepted == 1) {
            // If the syscall has not yet been released
            // restore the original system call in the table
            sys_call_table[i] = table[i].f;
        }
        // Free all the memory used for my_list.
        destroy_list(i);
        i++;
    }

    // Change the syscall table back to read only and give up the lock
    set_addr_ro((unsigned long)sys_call_table);
    spin_unlock(&sys_call_table_lock);

}

// Define the module init and exit functions.
module_init(init_function);
module_exit(exit_function);

