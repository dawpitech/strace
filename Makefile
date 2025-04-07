##
## EPITECH PROJECT, 2023
## makefile
## File description:
## makefile
##

SRC =   src/strace.c
OBJ = $(SRC:.c=.o)
NAME = strace
CFLAGS = -Wall -Wextra -Wpedantic -g3

all:    $(NAME)

$(NAME): $(OBJ)
	gcc $(OBJ) $(CFLAGS) -o $(NAME)

clean:
	@-rm -f $(OBJ)
	@-find . -name '*.gc*' -delete
	@-find . -name '*.log' -delete
	@-find . -name '*.*~' -delete
	@-find . -name '*.o' -delete

fclean: clean
	@-rm -f $(NAME)

re: fclean $(NAME)


.PHONY : all clean fclean re
