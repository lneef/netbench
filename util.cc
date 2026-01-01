#include "util.h"
#include <rte_launch.h>


int launch_lcores(int (*lcore_fn)(void *),  void *arg) {
  rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
          "tasks on %u worker lcores\n",
          rte_lcore_count() - 1);
  if(rte_eal_mp_remote_launch(lcore_fn, arg, CALL_MAIN)){
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "Failed to launch lcores\n");
      return -1;
  }

  rte_eal_mp_wait_lcore();
  return 0;
}
