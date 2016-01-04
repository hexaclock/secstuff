NAME     = libgmem.so
CC       = gcc
SRC      = pcalloc.c pfree.c pmalloc.c pmemalign.c prealloc.c
OBJ      = $(SRC:.c=.o)
RM       = rm -f
INCLPATH = ../include
LIBPATH  = ../lib
CFLAGS  += -I$(INCLPATH) -g -Wall

all:
	$(CC) $(CFLAGS) -c -fPIC $(SRC)
	$(CC) $(CFLAGS) -shared -o $(LIBPATH)/$(NAME) $(OBJ) -ldl
	-$(RM) $(NAME)
clean:
	-$(RM) *~ *.o *.core *.swp \#*
	-$(RM) $(NAME)
	-$(RM) $(LIBPATH)/$(NAME)

fclean: clean

re: fclean all
