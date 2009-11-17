# Makefile for jj
cflags = -g\
	-Wall\
	-DDEBUG\
	`pkg-config --cflags loudmouth-1.0`\

libs = 	`pkg-config --libs loudmouth-1.0`\

all: main.o
	gcc $(cflags) main.o -o jj $(libs)

main.o: main.c
	gcc -c $(cflags) main.c


.PHONY: check-syntax
# flymake
check-syntax:
	$(CXX) $(cflags) -Wextra -pedantic -fsyntax-only $(CHK_SOURCES)
