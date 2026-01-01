#ifndef UTIL_H
#define UTIL_H
#include <cstddef>
#include <cstdint>
#include <generic/rte_byteorder.h>
#include <netinet/in.h>
#include <rte_build_config.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_dyn.h>

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <vector>


static constexpr uint64_t CL_SIZE = RTE_CACHE_LINE_SIZE;
#define TTL 64
#define SWAP(a, b, T)                                                          \
  do {                                                                         \
    T temp = a;                                                                \
    a = b;                                                                     \
    b = temp;                                                                  \
  } while (0)

#define PUN(target, src, T)                                                    \
  do {                                                                         \
    rte_memcpy(target, src, sizeof(T));                                        \
  } while (0)
#define DPDK_LIFETIME_BEGIN {
#define DPDK_LIFETIME_END }

struct port_info;
struct benchmark_config;

struct lcore_adapter{
    port_info& info;
    benchmark_config& config;
};

typedef int (*packet_ipv4)(struct port_info *, struct rte_mbuf *);

int launch_lcores(int (*lcore_fn)(void *), void *arg);
template<typename>
struct padded;

template<typename T> requires ((sizeof(T) & (CL_SIZE - 1)) == 0)
struct padded<T> : public T{};   

template<typename T> requires ((sizeof(T) & (CL_SIZE - 1)) != 0)
struct padded<T> : public T{
    char pad[CL_SIZE - ((sizeof(T) & (CL_SIZE - 1)))];
};    

template<typename T>
struct dpdk_allocator{
    using value_type = T;
    static T* allocate(size_t n){
        return static_cast<T*>(rte_malloc(nullptr, sizeof(T) * n, CL_SIZE));
    }

    static void deallocate(T* ptr, __rte_unused std::size_t n){
        rte_free(ptr);
    }
};

template<typename T>
using aligned_vector = std::vector<padded<T>, dpdk_allocator<padded<T>>>;
#endif
