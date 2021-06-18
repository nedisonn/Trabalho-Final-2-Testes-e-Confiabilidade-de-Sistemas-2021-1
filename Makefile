# ==========================================
#   Unity Project - A Test Framework for C
#   Copyright (c) 2007 Mike Karlesky, Mark VanderVoord, Greg Williams
#   [Released under MIT License. Please refer to license.txt for details]
# ==========================================

#We try to detect the OS we are running on, and adjust commands as needed
ifeq ($(OS),Windows_NT)
  ifeq ($(shell uname -s),) # not in a bash-like shell
	CLEANUP = del /F /Q
	MKDIR = mkdir
  else # in a bash-like shell, like msys
	CLEANUP = rm -f
	MKDIR = mkdir -p
  endif
	TARGET_EXTENSION=.exe
else
	CLEANUP = rm -f
	MKDIR = mkdir -p
	TARGET_EXTENSION=.out
endif

C_COMPILER=gcc
ifeq ($(shell uname -s), Darwin)
C_COMPILER=clang
endif

GCCFLAGS = -g -Wall -Wfatal-errors 
ALL = crypt
GCC = gcc

UNITY_ROOT=Unity

CFLAGS=-std=c99
CFLAGS += -Wall
CFLAGS += -Wextra
CFLAGS += -Wpointer-arith
CFLAGS += -Wcast-align
CFLAGS += -Wwrite-strings
CFLAGS += -Wswitch-default
CFLAGS += -Wunreachable-code
CFLAGS += -Winit-self
CFLAGS += -Wmissing-field-initializers
CFLAGS += -Wno-unknown-pragmas
CFLAGS += -Wstrict-prototypes
CFLAGS += -Wundef
CFLAGS += -Wold-style-definition

TARGET_BASE1=all_tests
TARGET1 = $(TARGET_BASE1)$(TARGET_EXTENSION)
SRC_FILES1=\
  $(UNITY_ROOT)/src/unity.c \
  $(UNITY_ROOT)/extras/fixture/src/unity_fixture.c \
  test/crypt_test.c \
  test/test_runners/crypt_test_Runner.c
INC_DIRS=-Isrc -I$(UNITY_ROOT)/src 
SYMBOLS=
SRC_FILES_CRYPT += $(wildcard src/*.c)

all: clean compile run

compile:
	$(C_COMPILER) $(CFLAGS) $(INC_DIRS) $(SYMBOLS) $(SRC_FILES_CRYPT) $(SRC_FILES1) -o $(TARGET1)

run:
	- ./$(TARGET1)

clean:
	$(CLEANUP) $(TARGET1)
	sudo rm -fr $(ALL) *.o cov* *.dSYM *.gcda *.gcno *.gcov

crypt: $(SRC_FILES)
	$(CC) $(CFLAGS) $^
	$(CC) *.o -o app
	rm -rf *.o

cov: crypt.c
	$(GCC) $(GCCFLAGS) -fprofile-arcs -ftest-coverage -o cov crypt.c
	$(C_COMPILER) $(CFLAGS) $(INC_DIRS) $(SYMBOLS) $(SRC_FILES1) -fprofile-arcs -ftest-coverage -o $(TARGET1)
	echo 'oi123' | ./cov | echo "saida"
	echo 'Yaya' | ./cov | echo "saida"
	echo '123oi' | ./cov | echo "saida"
	echo ' ' | ./cov | echo "saida"
	echo 'oi_12' | ./cov | echo "saida"
	echo 'oi1234' | ./cov | echo "saida" 
	echo 'Nedison' | ./cov | echo "saida"
	gcov -b crypt.gnco

ci: CFLAGS += -Werror
ci: compile