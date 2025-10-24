CC ?= gcc
PKG_CONFIG := $(shell command -v pkg-config 2>/dev/null)

# Try to get flags from pkg-config when available, otherwise fall back to common defaults
OQS_CFLAGS := $(if $(PKG_CONFIG),$(shell pkg-config --cflags liboqs),-I/usr/include)
OQS_LIBS   := $(if $(PKG_CONFIG),$(shell pkg-config --libs liboqs),-loqs)
OPENSSL_CFLAGS := $(if $(PKG_CONFIG),$(shell pkg-config --cflags openssl),-I/usr/include/openssl)
OPENSSL_LIBS   := $(if $(PKG_CONFIG),$(shell pkg-config --libs openssl),-lcrypto -lssl)

CFLAGS ?= -O2 -Wall -Wextra $(OQS_CFLAGS) $(OPENSSL_CFLAGS)
LDFLAGS ?= $(OQS_LIBS) $(OPENSSL_LIBS)

TARGET = pqc_benchmarks
SRCS = pqc_benchmarks.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean run install-deps

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS) *.csv

install-deps:
	echo "Install dependencies on Debian/Ubuntu (requires sudo):"
	echo "  sudo apt update && sudo apt install -y build-essential pkg-config liboqs-dev libssl-dev"
	echo "If liboqs is not available in your distro packages, build liboqs from source: https://github.com/open-quantum-safe/liboqs"
