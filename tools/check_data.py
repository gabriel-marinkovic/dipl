import collections
import struct
import subprocess
import os
import dataclasses
from typing import Dict, FrozenSet, List, Set, Tuple


def run_command(command_name, *args, silent=False, silent_errors=False):
    command = [command_name] + list(args)
    if not silent:
        print("CMD:", " ".join(command))
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not silent and result.stdout:
        print(result.stdout, end="")
    if not silent_errors and result.stderr:
        print("Error:", result.stderr, end="")
    return result.stdout, result.stderr


def fa(addr):
    return f"{addr:#0{18}x}"


def read_packed_string(file):
    size_format = "<Q"
    size_bytes = file.read(struct.calcsize(size_format))
    size, = struct.unpack(size_format, size_bytes)
    return file.read(size).decode("utf-8")


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

@dataclasses.dataclass(frozen=True)
class Module:
    preferred_name: str
    path: str
    preferred_base: int
    base: int
    size: int
    entry_point: int

def parse_modules(directory) -> Tuple[Module]:
    modules = {}
    for filename in os.listdir(directory):
        if not filename.endswith(".module"):
            continue
        file_path = os.path.join(directory_path, filename)

        record_format = "<BQQQQ"
        record_size = struct.calcsize(record_format)
        with open(file_path, "rb") as file:
            while True:
                record_bytes = file.read(record_size)
                if not record_bytes:
                    break

                loaded, entry_point, preferred_base, start, end = struct.unpack(record_format, record_bytes)
                module = Module(
                    entry_point=entry_point,
                    preferred_base=preferred_base,
                    base=start,
                    size=end - start,
                    preferred_name=read_packed_string(file),
                    path=read_packed_string(file),
                )
                assert module.size >= 0
                if loaded:
                    modules[module.base] = module
                else:
                    modules.pop(module.base, None)
    return tuple(modules.values())



def process_file(
    thread_idxs_from_instr: Dict[Instruction, Set[int]],
    thread_accesses: Set[ThreadAccess],
    thread_idx: int,
    file_path: str,
):
    record_format = "<HHQ"
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
            print(file.tell())
            record_bytes = file.read(record_size)
            if not record_bytes:
                break

            opcode, size, addr = struct.unpack(record_format, record_bytes)
            opcode_name = read_packed_string(file)

            print(opcode, opcode_name, size, fa(addr))

            is_instruction = (opcode != 0 and opcode != 1)
            if is_instruction:
                push_instr(instr)
                instr = InstructionWIP(
                    name=opcode_name,
                    address=addr,
                    size=size,
                )
                if not instr.name:
                    instr.name = "<UNKNOWN>"
            else:
                assert instr

                assert len(opcode_name) == 0
                op = Operand(is_read=(opcode == 0), address=addr, size=size)
                if op.is_read:
                    instr.src_ops.append(op)
                else:
                    instr.dst_ops.append(op)
        push_instr(instr)

directory_path = "build/src"

modules = parse_modules(directory_path)

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

for module in modules:
    print(module.preferred_name, module.base)
print("----------------------------------------")


@dataclasses.dataclass(frozen=True)
class InstructionToInstrument:
    module: Module
    name: str
    offset: int
    addr2line_output: str

    def runtime_address(self) -> int:
        return self.module.base + self.offset
    def preferred_address(self) -> int:
        return self.module.preferred_base + self.offset


instrumented = []
for addr, name in sorted(truly_shared_instruction_addresses):
    min_addr = float("inf")
    min_idx = -1
    for i in range(len(modules)):
        offset = addr - modules[i].base
        if offset < 0:
            continue
        if min_addr > offset:
            min_addr = offset
            min_idx = i

    module = modules[min_idx]
    offset = addr - module.base
    preferred_address = module.preferred_base + offset

    out, err = run_command(
        "addr2line", "-Cafipe", module.path, f"0x{preferred_address:x}",
        silent=True, silent_errors=True
    )
    addr2line = (out + err).strip()
    instrumented.append(InstructionToInstrument(module=module, name=name, offset=offset, addr2line_output=addr2line))

    print("{: <64}{: <12}0x{:x}".format(module.path, name, offset))

print("----------------------------------------")

instrumented_trimmed = []
for instr in instrumented:
    print(instr.addr2line_output)

print(len(instrumented_trimmed))

print("TO COPY-PASTE:")
for instr in instrumented:
    print(f"0x{instr.offset:x}")
