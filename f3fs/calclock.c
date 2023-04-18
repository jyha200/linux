#include "calclock.h"

void __ktprint(int depth, char *func_name, ktime_t time, unsigned long long count)
{
//    char char_buff[100], char_buff2[100]; // buffer for characterized numbers
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
ktime_t last_print = {0,};
ktime_t last_print2[PROF_CNT] = {0,};


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
  if (ktime_to_ms(diff2) >= 1000) {
    last_print2[idx] = time_[count - 1];
    printk(KERN_CONT "%d : %d times",idx, count_global[idx]);
    for (int i = 0 ; i < count - 1 ; i++) {
      printk(KERN_CONT " %llu",
        (u64)ktime_to_ns(ktime_global[idx][i])/count_global[idx]);
    }
    if (idx == 4) {
      printk(KERN_CONT " %llu", (u64)(time_[count]));
    }
    printk(KERN_CONT "\n");
    for (int i = 0 ; i < count - 1 ; i++) {
      ktime_global[idx][i] = 0;
    }
    count_global[idx] = 0;
  }
}
