#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include "bpf_insn.h"

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int bpf(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

int map_create(int val_size, int max_entries) {
  union bpf_attr attr = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = val_size,
    .max_entries = max_entries
  };
  int mapfd = bpf(BPF_MAP_CREATE, &attr);
  if (mapfd == -1) fatal("bpf(BPF_MAP_CREATE)");
  return mapfd;
}

int map_update(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (unsigned long)&key,
    .value = (unsigned long)pval,
    .flags = BPF_ANY
  };
  int res = bpf(BPF_MAP_UPDATE_ELEM, &attr);
  if (res == -1) fatal("bpf(BPF_MAP_UPDATE_ELEM)");
  return res;
}

int map_lookup(int mapfd, int key, void *pval) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key = (unsigned long)&key,
    .value = (unsigned long)pval,
    .flags = BPF_ANY
  };
  return bpf(BPF_MAP_LOOKUP_ELEM, &attr); // -1 if not found
}

int main() {
  char verifier_log[0x10000];

  /* prepare the bpf map */
  unsigned long val;
  int mapfd = map_create(sizeof(val), 4);

  val = 0xdeadbeef;
  map_update(mapfd, 1, &val);
  val = 0xcafebabe;
  map_update(mapfd, 2, &val);

  /* prepare the bpf program */
  struct bpf_insn insns[] = {
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 1),      // key=1
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0x1337), // val=0x1337
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),
    // store
    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem(mapfd, &k, &v)

    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x08, 2),      // key=2
    BPF_ST_MEM(BPF_DW, BPF_REG_FP, -0x10, 0x1338), // val=0x1338
    // arg1: mapfd
    BPF_LD_MAP_FD(BPF_REG_ARG1, mapfd),
    // arg2: key pointer
    BPF_MOV64_REG(BPF_REG_ARG2, BPF_REG_FP),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG2, -8),
    // arg3: value pointer
    BPF_MOV64_REG(BPF_REG_ARG3, BPF_REG_2),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_ARG3, -8),
    // arg4: flags
    BPF_MOV64_IMM(BPF_REG_ARG4, 0),
    // store
    BPF_EMIT_CALL(BPF_FUNC_map_update_elem), // map_update_elem(mapfd, &k, &v)

    // socket filter; Cut off after the 4th bytes from the top
    BPF_MOV64_IMM(BPF_REG_0, 4),
    BPF_EXIT_INSN(),
  };

  /* setup as socket filter */
  union bpf_attr prog_attr = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (unsigned long)insns,
    .license = (unsigned long)"GPL v2",
    .log_level = 2,
    .log_size = sizeof(verifier_log),
    .log_buf = (unsigned long)verifier_log
  };

  /* load the BPF program */
  int progfd = bpf(BPF_PROG_LOAD, &prog_attr);
  if (progfd == -1) {
    fatal("bpf(BPF_PROG_LOAD)");
  }

  /* make sockets */
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    fatal("socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    fatal("setsockopt");

  /* use the map */
  map_lookup(mapfd, 1, &val);
  printf("val (before): 0x%lx\n", val);
  map_lookup(mapfd, 2, &val);
  printf("val (before): 0x%lx\n", val);

  /* use the socket */
  write(socks[1], "Hello", 5);

  /* use the map */
  map_lookup(mapfd, 1, &val);
  printf("val (after) : 0x%lx\n", val);
  map_lookup(mapfd, 2, &val);
  printf("val (after) : 0x%lx\n", val);

  /* use the socket */
  char buf[0x10] = {};
  read(socks[0], buf, 0x10);
  printf("Received: %s\n", buf);

  char c[1];
  scanf("%c%c", c, c);
  return 0;
}
