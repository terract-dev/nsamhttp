ASM     = nasm
ASMFLAGS = -f elf64
LD      = ld
LDFLAGS = -lssl -lcrypto -lc -dynamic-linker /lib64/ld-linux-x86-64.so.2
TARGET  = nasmhttp

SRCS    = src/main.asm \
          src/socket.asm \
          src/tls.asm \
          src/http.asm \
          src/response.asm \
          src/methods.asm \
          src/router.asm \
          src/headers.asm \
          src/static.asm

OBJS    = $(SRCS:.asm=.o)

.PHONY: all clean certs

all: $(TARGET)

%.o: %.asm
	$(ASM) $(ASMFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) -o $@ $^ $(LDFLAGS)

certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 \
		-keyout certs/key.pem \
		-out certs/cert.pem \
		-days 365 -nodes \
		-subj "/CN=localhost"

clean:
	rm -f src/*.o $(TARGET)
	rm -rf certs

run: all certs
	./$(TARGET)

