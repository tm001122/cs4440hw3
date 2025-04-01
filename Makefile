CXX=g++
CC=g++
CPPFLAGS=-Wall -Werror -O2

TARGET=twig
SRCS=${wildcard *.cc}
OBJECTS=${SRCS:.cc=.o}
HEADERS=${wildcard *.h}

all: $(TARGET)

$(TARGET): $(OBJECTS) 
	$(CXX) $(CPPFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJECTS): $(HEADERS)


tests: test
test: $(TARGET)
	-chmod a+rx test.x test.[0-9]*
	-./test.11
	-./test.12
	-./test.1
	-./test.2
	-./test.3
	-./test.4
	-./test.5
	-./test.6
	-./test.7
	-./test.8
	-./test.9
	-./test.10

clean:
	rm -f $(TARGET) *.o *.dmp.myoutput *.dmp.correct
