FLAGS = -Wall -Wextra -O0 -g3 -I.

ifeq ($(OS),Windows_NT)
    EXT = .exe
	FLAGS += -lws2_32 -lbcrypt
else
	EXT = .out
	FLAGS += -lssl -lcrypto -DHTTPS_ENABLED
endif

all: cweb.h cozisnews$(EXT)

cweb.h: src/main.c src/main.h
	python amalg.py

cweb.o: cweb.c
	gcc $< -o $@ -I3p

sqlite3.o: 3p/sqlite3.c
	gcc -c -o $@ $<

cozisnews$(EXT): demo/main.c sqlite3.o
	gcc -o $@ demo/main.c sqlite3.o $(FLAGS) -I3p

clean:
	rm *.o *.out *.exe
