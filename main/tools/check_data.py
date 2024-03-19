import collections
import struct
import os
import dataclasses
from typing import List, Set


def fa(addr):
    return f"{addr:#0{18}x}"

@dataclasses.dataclass
class Operand:
    is_read: bool
    address: int
    size: int

@dataclasses.dataclass
class Instruction:
    name: str
    address: int
    size: int
    read_operands: List[Operand] = dataclasses.field(default_factory=list)
    write_operands: List[Operand] = dataclasses.field(default_factory=list)
    thread_idxs: Set[int] = dataclasses.field(default_factory=set)
    addresses_touched: Set[int] = dataclasses.field(default_factory=set)


def process_file(instr_from_addr, thread_idx, file_path):
    record_format = "<HHQQ"
    record_size = struct.calcsize(record_format)

    def push_instr(instr):
        if not instr:
            return
        if instr.address not in instr_from_addr:
            instr_from_addr[instr.address] = instr
        instr = instr_from_addr[instr.address]
        instr.thread_idxs.add(thread_idx)

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
                instr = Instruction(
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
                    instr.read_operands.append(op)
                else:
                    instr.write_operands.append(op)
        push_instr(instr)

def postprocess_instructions(instr_from_addr):
    # Populate `instr.addresess_touched`.
    for instr in instr_from_addr.values():
        for op in instr.read_operands + instr.write_operands:
            for offset in range(op.size):
                instr.addresses_touched.add(op.address + offset)


instr_from_addr = {}
directory_path = "install/client"
for thread_idx, filename in enumerate(os.listdir(directory_path)):
    if filename.endswith(".bin"):
        file_path = os.path.join(directory_path, filename)
        process_file(instr_from_addr, thread_idx, file_path)
postprocess_instructions(instr_from_addr)

addresses_touched_from_thread_idx = collections.defaultdict(set)
for instr in instr_from_addr.values():
    for tid in instr.thread_idxs:
        addresses_touched_from_thread_idx[tid].update(instr.addresses_touched)

shared_addresses = set()
for tid1 in addresses_touched_from_thread_idx:
    for tid2 in addresses_touched_from_thread_idx:
        if tid1 == tid2:
            continue
        intersection = set.intersection(
            addresses_touched_from_thread_idx[tid1],
            addresses_touched_from_thread_idx[tid2]
        )
        shared_addresses.update(intersection)

# Compute ranges of memory addresses which have been accessed by more than one thread.
ranges = set()
instruction_addresses_which_touch_shared_ranges = set()
for instr in instr_from_addr.values():
    try:
        for op in instr.read_operands + instr.write_operands:
            for offset in range(op.size):
                if (op.address + offset) in shared_addresses:
                    ranges.add((op.address, op.size))
                    if len(instr.thread_idxs) > 1 and instr.address <= 0x405000:
                        instruction_addresses_which_touch_shared_ranges.add(instr.address)
                    raise None
    except:
        pass
ranges = sorted(ranges)

print(len(instr_from_addr))
print(len(shared_addresses))
print(len(ranges))
print(len(instruction_addresses_which_touch_shared_ranges))

for addr in instruction_addresses_which_touch_shared_ranges:
    print(fa(addr), instr_from_addr[addr])
