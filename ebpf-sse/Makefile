SOURCES := $(wildcard *.kern.c)
FILES := $(SOURCES:.c=.o)
MAP_FINE_SRC := $(wildcard map-fine/*.kern.c)
MAP_FINE_OBJ := $(MAP_FINE_SRC:.c=.o)
MAP_FINE_USER_SRC := $(wildcard map-fine/*.user.c)
MAP_FINE_USER_OBJ := $(MAP_FINE_USER_SRC:.c=)
USER_SRC := $(wildcard *.user.c)
USER := $(USER_SRC:.c=)
BPF-CLANG := clang
BPF_CLANG_CFLAGS := -target bpf -g -Wall -O2 -c
INCLUDE := -I ../../linux/arch/x86/include/generated/uapi/ -I../../linux/include/ -I../../linux/include/arch/x86/include/ -I../../linux/tools/lib/
USER-CFLAGS := -g -I../../linux/usr/include -I../../linux/include -I../../linux/include/arch/x86/include/ -I../../linux/include/uapi -I../../linux/tools/lib/ -L../../linux/tools/lib/bpf/
BACKUP_INCLUDE := -I../linux/usr/include/ -I../linux/tools/lib/
BACKUP_USER-CFLAGS := -g -I../linux/usr/include -I../linux/tools/lib/ -L../linux/tools/lib/bpf/


all: $(FILES) $(USER)
	
test: test.c
	$(BPF-CLANG) $(INCLUDE) $(BPF_CLANG_CFLAGS) -o test test.c

$(FILES) : %.o : %.c
	$(BPF-CLANG) $(INCLUDE) $(BPF_CLANG_CFLAGS) -o $@ $<

$(USER) : % : %.c
	gcc $(USER-CFLAGS) $< -lbpf -o $@

.PHONY : clean

clean :
	rm $(FILES) $(USER)
