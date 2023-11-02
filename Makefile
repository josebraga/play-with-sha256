# Name of the output / executable file
TARGET = sha256

# Compiler
CC = g++

# Compiler flags
CFLAGS = -lcrypto

# Source files
SRC = sha256.cpp

# Makefile rules
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(CFLAGS)

clean:
	rm -f $(TARGET)
