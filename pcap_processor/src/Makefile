CXX      = clang++
NAME     = pcapstat
SRCS     = main.cpp basic_stats.cpp easy_search_pcap.cpp filter_ssl.cpp
OBJS     = $(SRCS:.cpp=.o)
#OPENSSL  = /usr/include/openssl
IPATH    = ../include
CXXFLAGS += -I$(IPATH) -std=c++11 -g -O2 -Wall -pedantic
LDLIBS   += -lpcap
RM       = rm -f

all: $(NAME)

$(NAME): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(NAME) $(OBJS) $(LDLIBS)

clean:
	-$(RM) *.o *~ \#*

fclean: clean
	-$(RM) $(NAME)

re: fclean all
