NAME     = test
VULN     = heap_overflow
SRC1     = $(NAME).c
SRC2     = $(VULN).c
OBJ1     = $(SRC1:.c=.o)
OBJ2     = $(SRC2:.c=.o)
IPATH    = ../include
CFLAGS  += -I$(IPATH) -g -Wall -pedantic-errors
LDFLAGS += -L../lib
LDLIBS  += -lgmem
RM       = rm -f

all: libgmem $(NAME) $(VULN)

$(NAME): $(OBJ1)

$(VULN): $(OBJ2)

libgmem:
	cd ../src; make

clean:
	-$(RM) *.o *~ \#*
	-$(RM) $(NAME) $(VULN)

fclean: clean
	cd ../src; make fclean

re: fclean all
