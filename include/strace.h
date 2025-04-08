/*
** EPITECH PROJECT, 2025
** strace
** File description:
** uwu
*/

#ifndef STRACE_H
    #define STRACE_H
    #define MAX_STRING_LEN 512

typedef struct syscall_s {
    int id;
    char *name;
    int argc;
    int args[6];
} syscall_t;

typedef struct args_s {
    int s_mode;
    int pid;
    char *command;
} args_t;

#endif
