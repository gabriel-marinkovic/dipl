import collections
import struct
import subprocess
import os
import dataclasses
from typing import Dict, FrozenSet, List, Set, Tuple


def run_command(command_name, *args):
    command = [command_name] + list(args)
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(result.stdout, end="")
    if result.stderr:
        print("Error:", result.stderr, end="")


def fa(addr):
    return f"{addr:#0{18}x}"

@dataclasses.dataclass(frozen=True)
class Operand:
    is_read: bool
    address: int
    size: int

@dataclasses.dataclass(frozen=True)
class Instruction:
    name: str
    address: int
    size: int
    src_ops: Tuple[Operand]
    dst_ops: Tuple[Operand]
    addresses_read: FrozenSet[int]
    addresses_written: FrozenSet[int]
    addresses_touched: FrozenSet[int]


@dataclasses.dataclass
class InstructionWIP:
    name: str
    address: int
    size: int
    src_ops: List[Operand] = dataclasses.field(default_factory=list)
    dst_ops: List[Operand] = dataclasses.field(default_factory=list)

    def frozen(self):
        addr_w = set()
        addr_r = set()
        for op in self.src_ops + self.dst_ops:
            for offset in range(op.size):
                if op.is_read:
                    addr_r.add(op.address)
                else:
                    addr_w.add(op.address)
        return Instruction(
            name=self.name,
            address=self.address,
            size=self.size,
            src_ops=tuple(sorted(self.src_ops)),
            dst_ops=tuple(sorted(self.dst_ops)),
            addresses_read=frozenset(addr_r),
            addresses_written=frozenset(addr_w),
            addresses_touched=frozenset(addr_r | addr_w),
        )


@dataclasses.dataclass(frozen=True)
class ThreadAccess:
    thread_idx: int
    instr_addr: int
    instr_name: str
    read_addrs: FrozenSet[int]
    write_addrs: FrozenSet[int]


# Dict[int, Dict[int, Tuple[Tuple[Tuple[]]]]]
def process_file(
    thread_idxs_from_instr: Dict[Instruction, Set[int]],
    thread_accesses: Set[ThreadAccess],
    thread_idx: int,
    file_path: str,
):
    record_format = "<HHQQ"
    record_size = struct.calcsize(record_format)

    def push_instr(instr):
        if not instr:
            return
        frozen = instr.frozen()
        for op in frozen.src_ops + frozen.dst_ops:
            thread_idxs_from_instr[frozen].add((thread_idx, op.is_read))
        thread_accesses.add(ThreadAccess(
            thread_idx=thread_idx,
            instr_addr=frozen.address,
            instr_name=frozen.name,
            read_addrs=frozen.addresses_read,
            write_addrs=frozen.addresses_written,
        ))

    with open(file_path, "rb") as file:
        instr = None
        while True:
            record_bytes = file.read(record_size)
            if not record_bytes:
                break

            opcode, size, addr, opcode_name_length = struct.unpack(record_format, record_bytes)

            is_instruction = (opcode != 0 and opcode != 1)
            if is_instruction:
                push_instr(instr)
                instr = InstructionWIP(
                    name=file.read(opcode_name_length).decode("utf-8"),
                    address=addr,
                    size=size,
                )
                if not instr.name:
                    instr.name = "<UNKNOWN>"
            else:
                assert instr
                assert opcode_name_length == 0
                op = Operand(is_read=(opcode == 0), address=addr, size=size)
                if op.is_read:
                    instr.src_ops.append(op)
                else:
                    instr.dst_ops.append(op)
        push_instr(instr)

directory_path = "build/src"
thread_idxs_from_instr: Dict[Instruction, Set[Tuple[int, bool]]] = collections.defaultdict(set)
thread_accesses: Set[ThreadAccess] = set()
for thread_idx, filename in enumerate(os.listdir(directory_path)):
    if not filename.endswith(".bin"):
        continue
    file_path = os.path.join(directory_path, filename)
    file_size = os.path.getsize(file_path)
    if file_size > 1024**2:
        print("skipping", filename, "cause too large:", file_size / 1024**2, "MB")
        continue
    process_file(thread_idxs_from_instr, thread_accesses, thread_idx, file_path)

print(len(thread_idxs_from_instr))
print(len(thread_accesses))


shared_memory = set()
for a1 in thread_accesses:
    for a2 in thread_accesses:
        if a1.thread_idx == a2.thread_idx:
            continue
        mem_intersection = (a1.write_addrs & a2.read_addrs) | (a1.read_addrs & a2.write_addrs)
        shared_memory.update(mem_intersection)
print(shared_memory)
truly_shared_instruction_addresses = set()
for instr in thread_idxs_from_instr.keys():
    if instr.addresses_touched & shared_memory:
        truly_shared_instruction_addresses.add((instr.address, instr.name))

print(len(truly_shared_instruction_addresses))
print("----------------------------------------")

module_starts = sorted([
    (0x0, "build/example/double_checked_locking"),
    (0x72000000, "/lib64/libclient.so"),
    (0x7fd562200000, "/lib64/libdynamorio.so"),
    (0x7fd5624e0000, "/lib64/ld-linux-x86-64.so.2"),
    (0x7fff41b78000, "/lib64/[vdso]"),
    (0x7fd36143b000, "/lib64/libc.so.6"),
    (0x7fd56203d000, "/lib64/libm.so.6"),
    (0x7fd562447000, "/lib64/libgcc_s-13-20240316.so.1"),
    (0x7fd361c00000, "/lib64/libstdc++.so.6.0.32"),
])
to_resolve = []
for addr, name in sorted(truly_shared_instruction_addresses):
    min_addr = float("inf")
    min_idx = -1
    for i in range(len(module_starts)):
        a = addr - module_starts[i][0]
        if a < 0:
            continue
        if min_addr > a:
            min_addr = a
            min_idx = i
    module_start, module_path = module_starts[min_idx]
    offset = addr - module_start
    to_resolve.append((name, module_path, offset))
    print("{: <48}{: <12}0x{:x}".format(module_path, name, offset))

print("----------------------------------------")
for instr_name, module_path, offset in to_resolve:
    run_command("addr2line", "-Cfiape", module_path, f"0x{offset:x}")
    print("")
