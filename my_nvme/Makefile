# SPDX-License-Identifier: GPL-2.0


obj-m			+= nvme-core.o
obj-m		+= nvme.o

nvme-core-y				+= core.o ioctl.o
nvme-core-$(CONFIG_NVME_VERBOSE_ERRORS)	+= constants.o
nvme-core-$(CONFIG_NVME_MULTIPATH)	+= multipath.o
nvme-core-$(CONFIG_BLK_DEV_ZONED)	+= zns.o
nvme-core-$(CONFIG_FAULT_INJECTION_DEBUG_FS)	+= fault_inject.o
nvme-core-$(CONFIG_NVME_HWMON)		+= hwmon.o
nvme-core-$(CONFIG_NVME_AUTH)		+= auth.o

nvme-y					+= pci.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
