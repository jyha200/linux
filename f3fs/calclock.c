#include <linux/rwsem.h>
#include "calclock.h"

void __ktprint(int depth, char *func_name, ktime_t time, unsigned long long count)
{
    int percentage;
    static ktime_t totaltime = 1;

    if (ktime_before(totaltime, time))
        totaltime = time;
    percentage = time * 10000 / totaltime;

    printk("%s", "");

    while(depth--)
        printk(KERN_CONT "    ");
    printk(KERN_CONT "%s is called ", func_name);
    printk(KERN_CONT "%llu times, ", count);
    printk(KERN_CONT "and the time interval is %lluns (per thread is %lluns)", 
            (u64)ktime_to_ns(time), 
            (u64)(ktime_to_ns(time) / num_online_cpus()));
    printk(KERN_CONT " (%d.%.2d%%)\n", percentage/100, percentage%100);
}
#define PROF_CNT (30)

struct calclock global_total = {0,};
ktime_t ktime_global[PROF_CNT][10] = {0,};
int count_global[PROF_CNT] = {0,};
ktime_t ktime_global3[PROF_CNT] = {0,};
int count_global3[PROF_CNT] = {0,};
ktime_t ktime_global4[PROF_CNT] = {0,};
int count_global4[PROF_CNT] = {0,};

ktime_t last_print = {0,};
ktime_t last_print2[PROF_CNT] = {0,};
ktime_t last_print3 = 0;
ktime_t last_print4 = 0;

struct rw_semaphore print_lock4 = {0,};

void ktcond_print(ktime_t* time_) {
#if 0
  ktime_t diff = ktime_sub(time_[1], time_[0]);
  ktime_t diff2 = ktime_sub(time_[1], last_print);
  global_total.count++;
  global_total.time = ktime_add_safe(global_total.time, diff);
  if (ktime_to_ms(diff2) >= 1000) {
    last_print = time_[1];
    printk("first %llu tsmes, and the time interval is avg %lluns", global_total.count, 
        (u64)ktime_to_ns(global_total.time)/global_total.count);
    global_total.count = 0;
    global_total.time  = 0;
  }
#endif
}

void ktcond_print2(ktime_t* time_, int idx, int count) {
  ktime_t diff2 = ktime_sub(time_[count - 1], last_print2[idx]);
  for (int i = 0 ; i < count - 1 ; i++) {
    ktime_t diff = ktime_sub(time_[i+1], time_[i]);
    ktime_global[idx][i] = ktime_add_safe(ktime_global[idx][i], diff);
  }
  count_global[idx]++;
  if (idx == 4) {
    if (ktime_to_ms(diff2) >= 10000) {
      if (down_write_trylock(&print_lock4)) {
        for (int idx = 0 ; idx < 5 ; idx++) {
          int local_count = count_global[idx];
          if (local_count > 0) {
            count_global[idx] = 0;
            last_print2[idx] = time_[count - 1];
            printk(KERN_CONT "%d : %d times",idx, local_count);
            for (int i = 0 ; i < count - 1 ; i++) {
              printk(KERN_CONT " %llu",
                  (u64)ktime_to_ns(ktime_global[idx][i]));
            }
            printk(KERN_CONT " ");
            for (int i = 0 ; i < count - 1 ; i++) {
              ktime_global[idx][i] = 0;
            }
          }
        }
        printk(KERN_CONT "\n");
        up_write(&print_lock4);
      }
    }
  }
}

struct rw_semaphore print_lock = {0,};

void ktcond_print3(int idx, int count) {
  ktime_t cur = ktime_get_raw();
  ktime_t diff2;
  ktime_global3[idx] += count;
  count_global3[idx]++;
  diff2 = ktime_sub(cur, last_print3);
  if (ktime_to_ms(diff2) >= 1000) {
    if (down_write_trylock(&print_lock)) {
      last_print3 = cur;
      for (int i = 0 ; i < 6; i++) {
        {
          count_global3[i] = 0;
          printk(KERN_CONT "%d: %6llu ", i, (u64)ktime_to_ns(ktime_global3[i]));
          ktime_global3[i] = 0;
        }
      }
      printk(KERN_CONT "\n");
      up_write(&print_lock);
    }
  }
}

void ktcond_print4(int idx, int count) {
  ktime_t cur = ktime_get_raw();
  ktime_t diff2;
  ktime_global4[idx] += count;
  count_global4[idx]++;
  diff2 = ktime_sub(cur, last_print4);
  if (ktime_to_ms(diff2) >= 1000) {
    if (down_write_trylock(&print_lock4)) {
      last_print4 = cur;
      for (int i = 0 ; i < 9; i++) {
        int local_count = count_global4[i];
        if (local_count > 0) {
          count_global4[i] = 0;
          printk(KERN_CONT "%d: %6llu ", i, ktime_global4[i]/local_count);
          ktime_global4[i] = 0;
        } else {
          printk(KERN_CONT "%d: %6llu ", i, 0ULL);
        }
      }
      printk(KERN_CONT "\n");
      up_write(&print_lock4);
    }
  }
}
