project('dpdk-perf', 'cpp',
  version: '0.0.1',
  default_options: ['warning_level=2', 'cpp_std=c++20'])

dpdk_dep = dependency('libdpdk', method: 'pkg-config', required: true)

add_project_arguments('-D_POSIX_C_SOURCE=200809L', language: 'c')
add_project_arguments('-Wpedantic', language: 'c')

sources_ping = files('ping.cc',
  'packet.cc',
  'port.cc',
  'util.cc')
sources_pong = files('pong.cc',
  'packet.cc',
  'port.cc',
  'util.cc')

executable('dpdk-ping', sources_ping, dependencies: dpdk_dep)
executable('dpdk-pong', sources_pong, dependencies: dpdk_dep)

