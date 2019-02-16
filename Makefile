all: build-all

build-all:
	$(MAKE) -C kernel
	$(MAKE) -C rootprocess
	tar -H ustar -cf initrd.tar -C rootprocess/build/ rootprocess

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C rootprocess clean
	rm -f initrd.tar

qemu: build-all
	./qemu.sh
