#define IN_KERNEL2 (0)

#if IN_KERNEL2
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#else
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>
#include <stdio.h>
#endif

struct LNode {
  unsigned int start;
  unsigned int end;
  volatile struct LNode* next;
  unsigned int reader;
#if IN_KERNEL2
  struct rcu_head rcu;
#endif
};

struct ListRL {
  struct LNode* head;
};

struct RangeLock {
  struct LNode* node;
};

struct f3fs_rwsem3 {
  struct ListRL list_rl;
};

void init_f3fs_rwsem3(struct f3fs_rwsem3* sem);

struct RangeLock* MutexRangeAcquire(struct ListRL* list_rl,
  unsigned int start,
  unsigned int end,
  bool try);

void MutexRangeRelease(struct RangeLock* rl);

struct RangeLock* RWRangeTryAcquire(
  struct ListRL* list_rl,
  unsigned long long start,
  unsigned long long end,
  bool writer);

struct RangeLock* RWRangeAcquire(
  struct ListRL* list_rl,
  unsigned long long start,
  unsigned long long end,
  bool writer);

