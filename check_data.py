import collections
import struct
import os

thread_from_instr = collections.defaultdict(set)
opcode_from_instr = {}
def process_file(thread_idx, file_path):
    record_format = "<HHQQ"
    record_size = struct.calcsize(record_format)

    with open(file_path, "rb") as file:
        while True:
            record_bytes = file.read(record_size)
            if not record_bytes:
                break

            opcode, size, addr, opcode_name_length = struct.unpack(record_format, record_bytes)
            opcode_name_bytes = file.read(opcode_name_length)
            opcode_name = opcode_name_bytes.decode('utf-8')

            thread_from_instr[addr].add(thread_idx)
            opcode_from_instr[addr] = opcode_name

directory_path = "build/src"
for thread_idx, filename in enumerate(os.listdir(directory_path)):
    if filename.endswith(".bin"):
        file_path = os.path.join(directory_path, filename)
        process_file(thread_idx, file_path)

shared_instruction_addrs = []
for addr, thread_idxs in thread_from_instr.items():
    if len(thread_idxs) > 1:
        print(addr, thread_idxs, opcode_from_instr[addr])
        shared_instruction_addrs.append(addr)

print(len(shared_instruction_addrs))
print(len(opcode_from_instr))
