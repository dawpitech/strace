/*
** EPITECH PROJECT, 2025
** cli_args
** File description:
** uwu
*/

#include "../include/strace.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int parse_args(const int argc, char **argv, args_t *args)
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

void print_help(void)
{
    printf("USAGE: ./strace [-s] [-p <pid>|<command>]\n");
}

int get_args_end(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        if (argv[i][0] != '-')
            return i;
    return 1;
}
