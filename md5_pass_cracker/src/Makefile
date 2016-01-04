#CC       = /opt/gcc/bin/g++
CC       = clang++
NAME     = passcrack
SRCS     = md5hash.cpp main.cpp panic.cpp dictatk.cpp alrmh.cpp bruteatk.cpp numappatk.cpp leetatk.cpp pinatk.cpp siginth.cpp
OBJS     = $(SRCS:.c=.o)
CXXFLAGS += -I/usr/include/openssl -I../include -g -O2 -std=c++11
#LDFLAGS += -L../../openssl/ -Wl,--no-as-needed
LDLIBS  += -lssl -lcrypto
RM       = rm -f

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CXXFLAGS) -o $(NAME) $(OBJS) $(LDLIBS)

clean:
	-$(RM) *.o *~ \#*
	-$(RM) $(NAME)

fclean: clean

re: fclean all
