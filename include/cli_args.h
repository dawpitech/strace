/*
** EPITECH PROJECT, 2025
** cli_args
** File description:
** uwu
*/

#ifndef CLI_ARGS_H
    #define CLI_ARGS_H
    #include "strace.h"

int parse_args(const int argc, char **argv, args_t *args);
void print_help(void);
int get_args_end(int argc, char **argv);

#endif
