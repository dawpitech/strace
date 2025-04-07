/*
** EPITECH PROJECT, 2025
** strace
** File description:
** uwu
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include "../include/syscall.h"
#include <string.h>
#include <unistd.h>

#define MAX_STRING_LEN 512

void print_syscall(pid_t child, struct user_regs_struct *regs, args_t *args) {
    if (regs->orig_rax > 330)
        return;
    syscall_t *sys = &table[regs->orig_rax];

    printf("%s(", sys->name);
    unsigned long long args_[6] = {
        regs->rdi, regs->rsi, regs->rdx,
        regs->rcx, regs->r8, regs->r9,
    };

    for (int i = 0; i < sys->argc; i++) {
        if (i > 0)
            printf(", ");
	long arg = args_[i];

	if (!args->s_mode && sys->args[i] == VOID) {
	    printf("?");
	    continue;
	}
	if (!args->s_mode) {
	    printf("0x%X", (unsigned int)arg);
	    continue;
	}
        switch (sys->args[i]) {
            case NUM:
                printf("%lld", (unsigned long long)arg);
                break;
            case STRING:
                {
                    long long ptr = 0;
                    for (;; arg += sizeof arg) {
                        ptr = ptrace(PTRACE_PEEKDATA, child, arg, 0);
                        if ((long long)ptr == -1)
                            break;
                        printf("%.*s", (int)(sizeof ptr), (char *)&ptr);
                        if (memchr(&ptr, '\0', sizeof ptr) != NULL)
                            break;
                    }
                }
                break;
            case VOID_P:
                printf("%p", (void *)(arg));
                break;
            default:
                printf("?");
        }
    }
}

void trace_syscalls(pid_t child, args_t *args) {
    int status;
    struct user_regs_struct regs;
    char str[MAX_STRING_LEN] = {0};

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    waitpid(child, &status, 0);
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFEXITED(status))
            break;
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        print_syscall(child, &regs, args);
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFEXITED(status))
            break;
        ptrace(PTRACE_GETREGS, child, 0, &regs);
	if (args->s_mode) {
	    printf(") = %lld\n", regs.rax);
	} else {
	    printf(") = 0x%X\n", (unsigned int)regs.rax);
	}
        fflush(stdout);
    }
}

static int parse_args(int argc, char **argv, args_t *args)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0) {
            args->s_mode = 1;
            continue;
        }
        if (strcmp(argv[i], "-p") != 0) {
            args->command = argv[i];
            return (i + 1) < argc;
        }
        if ((i + 1) >= argc)
            return 1;
        args->pid = atoi(argv[i + 1]);
        return !(args->pid > 0) || (i + 2) < argc;
    }
    return 1;
}

int main(int argc, char **argv, char **envp) {
    args_t args = {0};
    pid_t pid = -1;

    if (argc < 2 || parse_args(argc, argv, &args))
        return 84;
    pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execve(argv[1], &argv[1], envp);
        return 84;
    } else {
        trace_syscalls(pid, &args);
    }
    return 0;
}
