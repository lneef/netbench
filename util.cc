#include "util.h"


int launch_lcores(int (**lcore_fn)(void *), struct port_info *arg,
                         uint16_t cores) {
  rte_log(RTE_LOG_INFO, RTE_LOGTYPE_USER1,
          "Launching %u tasks on %u worker lcores\n", cores,
          rte_lcore_count() - 1);
  uint16_t i = 0, lcore_id;
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_remote_launch(lcore_fn[i++], arg, lcore_id) < 0) {
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "Failed to launch lcore %u\n",
              lcore_id);
      return -1;
    }
  }

  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
      rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, "Failed to wait for lcore %d\n",
              lcore_id);
      return -1;
    }
  }
  return 0;
}
