CFLAGS=-c -Wall
LDFLAGS=-L. -lOpenAuth
LEGACYSOURCES=
SOURCES=main.cpp
OBJECTS=$(SOURCES:.cpp=.o) $(LEGACYSOURCES:.c=.o)
EXECUTABLE=OpenAuth
G++=g++
all: $(SOURCES) $(EXECUTABLE)
$(EXECUTABLE): $(OBJECTS)
	g++ --std=c++0x -g $(OBJECTS) $(LDFLAGS) -Wl,-rpath . -o $@
.c.o:
	gcc -g $(CFLAGS) $< -o $@
.cpp.o:
	g++ -std=c++0x -g -I../ $(CFLAGS) $< -o $@
gg:
	g++ --std=c++0x -g GGDNS.cpp GlobalGrid.cpp -I. -I../ -Iglobalgrid/ -o distauth -L. -lOpenAuth -Lglobalgrid -lGlobalGrid -luuid -pthread -Wl,-rpath .
	cp globalgrid/libGlobalGrid.so .
