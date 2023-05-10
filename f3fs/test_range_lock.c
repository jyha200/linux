#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

#include "range_lock.h"

void* test0_thread0(void* data) {
  struct f3fs_rwsem2* lock = (struct f3fs_rwsem2*)data;
  bool ret = false;

  f3fs_down_range(lock, 0, 0xFFFFFFFF, true);
  sleep(1);
  f3fs_up_range(lock, 0, 0xFFFFFFFF, true);
  sleep(0.5);
  assert(!f3fs_down_range_trylock(lock, 0,1, false));
  assert(f3fs_down_range_trylock(lock, 1, 0xFFFFFFFE, false));
  sleep(1);
  f3fs_up_range(lock, 1, 0xFFFFFFFE, false);
}

void* test0_thread1(void* data) {
  struct f3fs_rwsem2* lock = (struct f3fs_rwsem2*)data;
  sleep(0.5);
  assert(false == f3fs_down_range_trylock(lock, 0, 0x1, true));
  f3fs_down_range(lock, 0, 0x1, true);
  sleep(1);
  assert(f3fs_down_range_trylock(lock, 1, 0xFFFFFFFE, false));
  f3fs_up_range(lock, 1, 0xFFFFFFFE, false);
  f3fs_up_range(lock, 0, 0x1, true);
}

int main(void) {
  struct f3fs_rwsem2 lock;
  pthread_t pthread[2] = {0,};
  init_f3fs_rwsem2(&lock);
  printf("start\n");

  // test0
  pthread_create(&pthread[0], NULL, test0_thread0, &lock);
  pthread_create(&pthread[1], NULL, test0_thread1, &lock);

  pthread_join(pthread[0], NULL);
  pthread_join(pthread[1], NULL);
  printf("end\n");

  return 0;
}
