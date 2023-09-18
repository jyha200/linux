#include "lockfree_list.h"

#if IN_KERNEL2
#define mem_alloc(size) kmalloc(size, GFP_KERNEL)
#define mem_free(ptr) kfree(ptr)
#define CAS(ptr, cur, next) cmpxchg(ptr, cur, next) == cur

#define RCU_LOCK() rcu_read_lock()
#define RCU_UNLOCK() rcu_read_unlock()
#define RCU_DREF(ptr) rcu_dereference(ptr)
#define RCU_KFREE(ptr) kfree_rcu(ptr, rcu)
#else
#define mem_alloc(size) malloc(size)
#define mem_free(ptr) free(ptr)
#define CAS(ptr, cur, next) __sync_bool_compare_and_swap(ptr, cur, next)

#define RCU_LOCK()
#define RCU_UNLOCK()
#define RCU_DREF(ptr) ptr
#define RCU_KFREE(ptr)
#endif

void init_f3fs_rwsem3(struct f3fs_rwsem3* sem) {
  memset(&sem->list_rl, 0, sizeof(struct ListRL));
}

bool marked(volatile struct LNode* node) {
  return (unsigned long long)(node) & 0x1;
}

struct LNode* unmark(volatile struct LNode* node) {
  return (struct LNode*)((unsigned long long)(node) & 0xFFFFFFFFFFFFFFFE);
}

int compare(struct LNode* lock1, struct LNode* lock2) {
  if (!lock1) {
    return 1;
  }

  if (lock1->start >= lock2->end) {
    return 1;
  }
  if (lock2->start >= lock1->end) {
    return -1;
  }
  return 0;
}

int InsertNode(struct ListRL* listrl, struct LNode* lock, bool try) {
//  RCU_LOCK();
  while (true) {
    volatile struct LNode** prev = &listrl->head;
    struct LNode* cur = *prev;

    while (true) {
      if (marked(cur)){
        break;
      }
      else {
        if (cur && marked(cur->next)) {
          struct LNode* next = unmark(cur->next);

          if (CAS(prev, cur, next)) {
    //        RCU_KFREE(cur);
          }
          cur = next;
        } else {
          int ret = compare(cur, lock);

          if (ret == -1) {
            prev = &cur->next;
            cur = *prev;
          } else if (ret == 0) {
            if (try) {
            //  RCU_UNLOCK();

              return -1;
            }
            while (!marked(cur->next)) {
              cur = *prev;
            }
          } else if (ret == 1) {
            lock->next = cur;
            if (CAS(prev, cur, lock)) {
             // RCU_UNLOCK();

              return 0;
            }
            cur = *prev;
          }
        }
      }
    }
  }
//  RCU_UNLOCK();
  return -1;
}

struct RangeLock* MutexRangeAcquire(struct ListRL* list_rl,
  unsigned int start,
  unsigned int end,
  bool try) {
  struct RangeLock* rl = mem_alloc(sizeof(struct RangeLock));

  rl->node = mem_alloc(sizeof(struct LNode));
  rl->node->start = start;
  rl->node->end = end;
  rl->node->next = NULL;
  if (InsertNode(list_rl, rl->node, try) < 0) {
    mem_free(rl->node);
    mem_free(rl);
    return NULL;
  } else {
    return rl;
  }
}

void DeleteNode(struct LNode* lock) {
  while (true) {
    volatile struct LNode* orig = lock->next;
    unsigned long long marked = (unsigned long long)orig + 1;
    if (CAS(&lock->next, orig, (struct LNode*)marked)) {
      break;
    }
  }
}

void MutexRangeRelease(struct RangeLock* rl) {
  DeleteNode(rl->node);
  mem_free(rl);
}

int compareRW(struct LNode* lock1, struct LNode* lock2) {
  if (!lock1) {
    return 1;
  } else {
    int readers = lock1->reader + lock2->reader;
    if (lock2->start >= lock1->end) {
      return -1;
    }
    if (lock2->start >= lock1->start && readers == 2) {
      return -1;
    }
    if (lock1->start >= lock2->end) {
      return 1;
    }
    if (lock1->start >= lock2->start && readers == 2) {
      return 1;
    }
    return 0;
  }
}

int w_validate(struct ListRL* listrl, struct LNode* lock) {
  volatile struct LNode** prev = &listrl->head;
  struct LNode* cur = unmark(*prev);

  while (true) {
    if (!cur) {
      return 0;
    }

    if (cur == lock) {
      return 0;
    }
    if (marked(cur->next)) {
      struct LNode* next = unmark(cur->next);
      if (CAS(prev, cur, next)) {
        RCU_KFREE(cur);
      }
      cur = next;
    } else {
      if (cur->end <= lock->start) {
        prev = &cur->next;
        cur = unmark(*prev);
      } else {
        DeleteNode(lock);
        return 1;
      }
    }
  }
}

int r_validate(struct LNode* lock, bool try) {
  volatile struct LNode** prev = &lock->next;
  struct LNode* cur = unmark(*prev);

  while (true) {
    if (!cur) {
      return 0;
    }
    if (cur == lock) {
      return 0;
    }
    if (marked(cur->next)) {
      struct LNode* next = unmark(cur->next);
      if (CAS(prev, cur, next)) {
        RCU_KFREE(cur);
      }
      cur = next;
    }
    else if (cur->reader) {
      prev = &cur->next;
      cur = unmark(*prev);
    } else {
      if (try) {
        return -1;
      }
      while (!marked(cur->next)) {
        cur = *prev;
      }
    }
  }
}

int InsertNodeRW(struct ListRL* listrl, struct LNode* lock, bool try) {
  RCU_LOCK();
  while (true) {
    volatile struct LNode** prev = &listrl->head;
    struct LNode* cur = *prev;

    while (true) {
      if (marked(cur)){
        break;
      }
      else {
        if (cur && marked(cur->next)) {
          struct LNode* next = unmark(cur->next);

          if (CAS(prev, cur, next)) {
            RCU_KFREE(cur);
          }
          cur = next;
        } else {
          int ret = compareRW(cur, lock);

          if (ret == -1) {
            prev = &cur->next;
            cur = *prev;
          } else if (ret == 0) {
            if (try) {
              RCU_UNLOCK();

              return -1;
            }
            while (!marked(cur->next)) {
              cur = *prev;
            }
          } else if (ret == 1) {
            lock->next = cur;
            if (CAS(prev, cur, lock)) {
              int ret = 0;
              if (lock->reader) {
                ret = r_validate(lock, try);
              } else {
                ret = w_validate(listrl, lock);
              }

              RCU_UNLOCK();

              return ret;
            }
            cur = *prev;
          }
        }
      }
    }
  }
  RCU_UNLOCK();
  return -1;
}

struct RangeLock* RWRangeTryAcquire(
  struct ListRL* list_rl,
  unsigned long long start,
  unsigned long long end,
  bool writer) {
  struct RangeLock* rl = mem_alloc(sizeof(struct RangeLock));
  int ret = 0;
  rl->node = mem_alloc(sizeof(struct LNode));
  rl->node->start = start;
  rl->node->end = end;
  rl->node->next = NULL;
  rl->node->reader = !writer;
  do {
    ret = InsertNodeRW(list_rl, rl->node, true);
    if (ret < 0) {
      mem_free(rl->node);
      mem_free(rl);
      return NULL;
    }
  } while(ret); 
  return rl;
}

struct RangeLock* RWRangeAcquire(
  struct ListRL* list_rl,
  unsigned long long start,
  unsigned long long end,
  bool writer) {
  struct RangeLock* rl = mem_alloc(sizeof(struct RangeLock));
  int ret = 0;
  rl->node = mem_alloc(sizeof(struct LNode));
  rl->node->start = start;
  rl->node->end = end;
  rl->node->next = NULL;
  rl->node->reader = !writer;

  do {
    ret = InsertNodeRW(list_rl, rl->node, false);
  } while(ret); 
  return rl;
}
