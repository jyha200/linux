#include <linux/module.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/syscalls.h>
#include <linux/blkdev.h>
#include <linux/nvme.h>
#include <linux/pci.h>
#include <linux/nvme_ioctl.h>
#include <linux/cdev.h>
#include <linux/blk-mq.h>
#include "nvme.h"

MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

MODULE_IMPORT_NS(NVME_TARGET_PASSTHRU);
#define INVALID_OPCODE (0xFF)
#define MAX_DEVICES (32)
#define MAX_PATH_LEN (64)

static char* device_list = "";
static char* parsed_device_list[MAX_DEVICES];
static char validated_device_path[MAX_DEVICES][MAX_PATH_LEN] = {0,};
static int num_devices = 0;
static int cur_idx = 0;
static long polling_duration_ms = 1000;
static long timeout_ms = 50;
module_param(device_list, charp, 0);
module_param(polling_duration_ms, long, 0);
module_param(timeout_ms, long, 0);

void parse_device_list(void) {
  char* ret = strsep(&device_list, ",");
  while(ret) {
    parsed_device_list[num_devices] = ret;
    num_devices++;
    if (num_devices >= MAX_DEVICES) {
      printk("Max %d devices can be processed",  MAX_DEVICES);
      break;
    }
    ret = strsep(&device_list, ",");
  }
}

bool validate_path(char* path) {
  struct file* file = filp_open(path, O_RDONLY, 0);
  if (IS_ERR(file)) {
    return false;
  } else {
    filp_close(file, NULL);
    return true;
  }
}

void validate_device_list(void) {
  int count = 0;
  for (int i = 0 ; i < num_devices ; i++) {
    char target_path[MAX_PATH_LEN] = "/dev/";
    if (strlen(target_path) + strlen(parsed_device_list[i]) >= MAX_PATH_LEN) {
      printk("Too long path %s", parsed_device_list[i]);
      continue;
    }
    strcat(target_path, parsed_device_list[i]);
    {
      strcpy(validated_device_path[count], target_path);
      if (validate_path(validated_device_path[count]) == false) {
        printk("file open error");
        validated_device_path[count][0] = '\0';
      }
      count++;
    }
  }
  num_devices = count;
  for (int i = 0 ; i < num_devices ; i++) {
    printk("%d: %s", i, validated_device_path[i]);
  }
}

void remove_cur_dev(void) {
  validated_device_path[cur_idx][0] = 0;
}

int get_next_nvme_dev(void) {
  if (num_devices > 0) {
    cur_idx = (cur_idx + 1) % num_devices;
  }
  return cur_idx;
}


int watchdog_fn(void* arg) {
  int no_device_list = strlen(device_list) == 0;
  struct file* devs[MAX_DEVICES] = {0,};
  struct device* raw_devs[MAX_DEVICES] = {0,};
  struct nvme_command c;
  unsigned timeout = msecs_to_jiffies(timeout_ms);
  memset(&c, 0x0, sizeof(struct nvme_command));
  c.common.opcode = INVALID_OPCODE;
  parse_device_list();
  validate_device_list();

  for (int i = 0 ; i < num_devices ; i++) {
    if (validated_device_path[i][0] != '\0') {
      devs[i] = filp_open(validated_device_path[i], O_RDWR, 0);
      {
        struct nvme_ctrl* ctrl = devs[i]->private_data;
        struct nvme_ns* ns = nvme_find_get_ns(ctrl, 1);
        struct gendisk* gendisk = ns->disk;
        raw_devs[i] = disk_to_dev(gendisk);
        nvme_put_ns(ns);
      }
    }
  }
  while(!kthread_should_stop()) {
    if (no_device_list) {
//      printk("no device input");
    } else {
      int idx = get_next_nvme_dev();
      if (devs[idx] == NULL) {
//        printk("no valid nvme device");
      } else {
        int ret = 0;
        u64 result = 0;
        struct file* dev = devs[idx];
        unsigned int inflights[2];
        long long time_diff;
        struct nvme_ctrl* ctrl = devs[idx]->private_data;
        ktime_t start_time, end_time;
        part_inflight_get(raw_devs[idx], NULL, inflights);
        start_time = ktime_get();
        ret = nvme_submit_user_cmd(ctrl->admin_q, &c, NULL, 0, NULL, 0, 0, &result, timeout, false);
        end_time = ktime_get();
        time_diff = ktime_to_ns(ktime_sub(end_time, start_time));
        printk("inflights %u %u , duration %lld ns", inflights[0], inflights[1], time_diff);
        if (ret == -4) {
          if (validate_path(validated_device_path[idx])) {
            printk("inference failed");
          } else {
            filp_close(dev, NULL);
            devs[idx] = NULL;
            printk("device failure detected");
          }
        }
      }
    }
    msleep(polling_duration_ms);
  }

  for (int i = 0 ; i < num_devices; i++) {
    if (devs[i]) {
      filp_close(devs[i], NULL);
    }
  }

  return 0;
}

static struct task_struct* watchdog_task = NULL;

static int watchdog_mod_init(void) {

  printk("%s\n", __func__);

  watchdog_task = kthread_run(watchdog_fn, NULL, "pcie_watchdog");
  if (watchdog_task) {
    printk("watchdog added\n");
  } else {
    printk("watchdog failed\n");
  }
  return 0;

}

static void watchdog_mod_exit(void) {
  printk("%s\n", __func__);
  if (watchdog_task) {
    kthread_stop(watchdog_task);
  }
}

module_init(watchdog_mod_init);
module_exit(watchdog_mod_exit);
