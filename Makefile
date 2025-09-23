FLAGS = -Wall -Wextra -O0 -g3 -I.

ifeq ($(OS),Windows_NT)
    EXT = .exe
	FLAGS += -lws2_32 -lbcrypt
else
	EXT = .out
endif

all: cweb.c cweb.h cozisnews$(EXT)

cweb.c cweb.h: src/main.c src/main.h
	python amalg.py

sqlite3.o: demo/sqlite3.c
	gcc -o $@ -c $<

cozisnews$(EXT): demo/main.c cweb.c cweb.h sqlite3.o
	gcc -o $@ demo/main.c demo/chttp.c demo/wl.c cweb.c sqlite3.o $(FLAGS) -Idemo

clean:
	rm *.o *.out *.exe
