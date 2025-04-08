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
#include "../include/cli_args.h"
#include <string.h>
#include <unistd.h>

static int print_string(pid_t child, long arg)
{
    long long ptr = 0;
    int tot = 0;

    tot += printf("\"");
    for (;; arg += sizeof arg) {
        ptr = ptrace(PTRACE_PEEKDATA, child, arg, 0);
        if ((long long)ptr == -1)
            break;
        tot += printf("%.*s", (int)(sizeof ptr), (char *)&ptr);
        if (memchr(&ptr, '\0', sizeof ptr) != NULL)
            break;
    }
    tot += printf("\"");
    return tot;
}

static int print_type(pid_t child, long arg, syscall_t *sys, int i)
{
    switch (sys->args[i]) {
        case NUM:
            return printf("%lld", (unsigned long long)arg);
        case STRING:
            return print_string(child, arg);
        case VOID_P:
            return printf("%p", (void *)(arg));
        default:
            return printf("?");
    }
}

static int iterate_args(pid_t child, syscall_t *sys, args_t *args,
    unsigned long long *args_)
{
    long arg = 0;
    int tot = 0;

    for (int i = 0; i < sys->argc; i++) {
        if (i > 0)
            tot += printf(", ");
        arg = args_[i];
        if (!args->s_mode && sys->args[i] == VOID) {
            tot += printf("?");
            continue;
        }
        if (!args->s_mode) {
            tot += printf("0x%x", (unsigned int)arg);
            continue;
        }
        tot += print_type(child, arg, sys, i);
    }
    return tot;
}

int print_syscall(pid_t child, struct user_regs_struct *regs, args_t *args)
{
    syscall_t *sys = NULL;
    int tot = 0;
    unsigned long long args_[6] = {
        regs->rdi, regs->rsi, regs->rdx,
        regs->rcx, regs->r8, regs->r9,
    };

    if (regs->rax > 330)
        return tot;
    sys = &table[regs->rax];
    tot += printf("%s(", sys->name);
    tot += iterate_args(child, sys, args, args_);
    return tot;
}

static void print_ret(args_t *args, struct user_regs_struct *regs, int tot)
{
    syscall_t *sys = NULL;
    int off = 1;

    if (regs->rax <= 330) {
        sys = &table[regs->rax];
    }
    if (sys != NULL && strcmp(sys->name, "exit_group") == 0)
        args->exit_code = regs->rdi;
    tot += printf(")");
    if (tot < 40)
        off = 40 - tot;
    if (sys != NULL && sys->args[sys->argc] == VOID) {
        printf("%*s= ?\n", off, "");
    } else if (!args->s_mode){
        printf("%*s= 0x%X\n", off, "", (unsigned int)regs->rax);
    } else {
        printf("%*s= %lld\n", off, "", regs->rax);
    }
    fflush(stdout);
}

static int maybe_print_syscall(unsigned char *instr, pid_t child,
    args_t *args, struct user_regs_struct *regs)
{
    int status = 0;
    int tot = 0;

    if (instr[0] == 0x0F && instr[1] == 0x05) {
        tot += print_syscall(child, regs, args);
        ptrace(PTRACE_SINGLESTEP, child, 0, 0);
        waitpid(child, &status, 0);
        ptrace(PTRACE_GETREGS, child, 0, regs);
        print_ret(args, regs, tot);
        if (WIFEXITED(status))
            return 1;
    }
    return 0;
}

int trace_syscalls(pid_t child, args_t *args)
{
    int status;
    struct user_regs_struct regs;
    unsigned char instr[2];
    long data = 0;

    waitpid(child, &status, 0);
    while (1) {
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        data = ptrace(PTRACE_PEEKTEXT, child, (void *)regs.rip, 0);
        instr[0] = data & 0xFF;
        instr[1] = (data >> 8) & 0xFF;
        if (maybe_print_syscall(instr, child, args, &regs))
            break;
        ptrace(PTRACE_SINGLESTEP, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFEXITED(status))
            break;
    }
    return args->exit_code;
}

// ReSharper disable once CppJoinDeclarationAndAssignment
int main(const int argc, char **argv, char **envp)
{
    args_t args = {0};
    pid_t pid;

    if (argc < 2 || strcmp(argv[1], "-help") == 0
        || strcmp(argv[1], "--help") == 0
        || parse_args(argc, argv, &args))
        return print_help(), EXIT_FAILURE_TECH;
    pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execve(argv[get_args_end(argc, argv)], &argv[get_args_end(argc, argv)],
            envp);
        return EXIT_FAILURE_TECH;
    }
    printf("+++ exited with %d +++\n", trace_syscalls(pid, &args));
    return EXIT_SUCCESS;
}
