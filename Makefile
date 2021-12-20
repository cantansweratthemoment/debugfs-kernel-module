obj-m += kmod.o

all:
	@echo "Targets: clean, build, install"

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: build
	sudo insmod kmod.ko
