NAME     = proxyserver
SRCS     = connect_to_host.c get_listener.c panic.c main.c start_proxy.c add_tls_cli.c add_tls_srv.c get_time.c
OBJS     = $(SRCS:.c=.o)
OPENSSL  = /usr/include/openssl
IPATH    = ../include
CFLAGS  += -I$(OPENSSL) -I$(IPATH) -g -O2 -Wall -pedantic
#LDFLAGS += -L../../openssl/ -Wl,--no-as-needed
LDLIBS  += -ldl -lssl -lcrypto
RM       = rm -f

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $(NAME) $(OBJS) $(LDLIBS)

clean:
	-$(RM) *.o *~ \#*
	-$(RM) $(NAME)

fclean: clean

re: fclean all
