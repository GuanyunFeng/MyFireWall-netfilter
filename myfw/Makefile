KERN_DIR = /lib/modules/$(shell uname -r)/build
myfw-objs := myfw_mod.o #file2.o file3.o
obj-m += myfw.o

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   
clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
	rm -f *.symvers
