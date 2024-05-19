import argparse
import atexit
import collections
import dataclasses
import os
import psutil
import shutil
import struct
import subprocess
import threading
import time
from typing import DefaultDict, FrozenSet, List, Set, Tuple


def run_command(command_name, *args, silent=False, silent_errors=False):
    command = [command_name] + list(args)
    if not silent:
        print("CMD:", " ".join(command))
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if not silent and result.stdout:
        print(result.stdout, end="")
    if not silent_errors and result.stderr:
        print("Error:", result.stderr, end="")
    return result.stdout, result.stderr


def kill_process_and_descendants(process):
    try:
        parent = psutil.Process(process.pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        parent.kill()
    except psutil.NoSuchProcess:
        pass


def fa(addr):
    return f"{addr:#0{18}x}"


def read_packed_string(file):
    size_format = "<Q"
    size_bytes = file.read(struct.calcsize(size_format))
    (size,) = struct.unpack(size_format, size_bytes)
    return file.read(size).decode("utf-8")


def write_packed_bool8(file, x):
    file.write(struct.pack("<B", x))


def write_packed_int64(file, x):
    file.write(struct.pack("<Q", x))


def write_packed_string(file, s):
    write_packed_int64(file, len(s))
    file.write(s.encode("utf-8"))


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


@dataclasses.dataclass(frozen=True)
class InstructionToInstrument:
    module: Module
    name: str
    offset: int
    access_count1: int
    access_count2: int
    addr2line_output: str

    def runtime_address(self) -> int:
        return self.module.base + self.offset

    def preferred_address(self) -> int:
        return self.module.preferred_base + self.offset


def parse_modules(directory) -> Tuple[Module]:
    modules = {}
    for filename in os.listdir(directory):
        if not filename.endswith(".module"):
            continue
        file_path = os.path.join(directory, filename)

        record_format = "<BQQQQ"
        record_size = struct.calcsize(record_format)
        with open(file_path, "rb") as file:
            while True:
                record_bytes = file.read(record_size)
                if not record_bytes:
                    break

                loaded, entry_point, preferred_base, start, end = struct.unpack(
                    record_format, record_bytes
                )
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
    thread_idxs_from_instr: DefaultDict[Instruction, List[int]],
    thread_accesses: Set[ThreadAccess],
    memory_hints: List[Set[int]],
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
            thread_idxs_from_instr[frozen].append(thread_idx)
        if frozen.name == "syscall":
            thread_idxs_from_instr[frozen].append(thread_idx)
        thread_accesses.add(
            ThreadAccess(
                thread_idx=thread_idx,
                instr_addr=frozen.address,
                instr_name=frozen.name,
                read_addrs=frozen.addresses_read,
                write_addrs=frozen.addresses_written,
            )
        )

    with open(file_path, "rb") as file:
        instr = None
        while True:
            record_bytes = file.read(record_size)
            if not record_bytes:
                break

            opcode, size, addr = struct.unpack(record_format, record_bytes)
            opcode_name = read_packed_string(file)

            if opcode == 2:
                # Memory hint entry.
                def f(memory_hints, addr, size):
                    addrs = list(range(addr, addr + size))
                    for addr in addrs:
                        for block in memory_hints:
                            if addr in block:
                                block.update(addrs)
                                return
                    memory_hints.append(set(addrs))

                f(memory_hints, addr, size)
                continue

            is_instruction = opcode > 2
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


def get_instructions_to_instrument(
    collect_directory: str,
) -> List[InstructionToInstrument]:
    modules = parse_modules(collect_directory)

    thread_idxs_from_instr: DefaultDict[Instruction, List[int]] = (
        collections.defaultdict(list)
    )
    thread_accesses: Set[ThreadAccess] = set()
    memory_hints: List[Set[int]] = []
    thread_idx = 0
    for filename in os.listdir(collect_directory):
        if not filename.endswith(".bin"):
            continue
        file_path = os.path.join(collect_directory, filename)
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            continue
        if file_size > 1024**2:
            print("skipping", filename, "cause too large:", file_size / 1024**2, "MB")
            continue
        process_file(
            thread_idxs_from_instr, thread_accesses, memory_hints, thread_idx, file_path
        )
        thread_idx += 1

    def with_hints(hints, addrs):
        new_addrs = addrs.copy()
        for block in memory_hints:
            if new_addrs & block:
                new_addrs |= block
        return new_addrs

    shared_memory = set()
    for a1 in thread_accesses:
        for a2 in thread_accesses:
            if a1.thread_idx == a2.thread_idx:
                continue
            mem_intersection = (
                with_hints(memory_hints, a1.write_addrs)
                & with_hints(memory_hints, a2.read_addrs)
            ) | (
                with_hints(memory_hints, a2.write_addrs)
                & with_hints(memory_hints, a1.read_addrs)
            )
            shared_memory.update(mem_intersection)
    print(f"{len(shared_memory)=}")

    truly_shared_instruction_addresses = set()
    for instr in thread_idxs_from_instr.keys():
        if (instr.addresses_touched & shared_memory) or instr.name == "syscall":
            truly_shared_instruction_addresses.add((instr.address, instr.name))
    print(f"{len(truly_shared_instruction_addresses)=}")

    access_count_per_instruction_address = {}
    for instr, thread_idxs in thread_idxs_from_instr.items():
        counter = collections.Counter(thread_idxs)
        assert any(thread_idx in counter for thread_idx in [0, 1]) and "2 thread limit"
        access_count_per_instruction_address[instr.address] = counter

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
            "addr2line",
            "-Cafipe",
            module.path,
            f"0x{preferred_address:x}",
            silent=True,
            silent_errors=True,
        )
        addr2line = (out + err).strip()
        instrumented.append(
            InstructionToInstrument(
                module=module,
                name=name,
                offset=offset,
                access_count1=access_count_per_instruction_address[addr][0],
                access_count2=access_count_per_instruction_address[addr][1],
                addr2line_output=addr2line,
            )
        )

        print(
            "{: <64}{: <12}0x{:x} ({} times)".format(
                module.path, name, offset, access_count_per_instruction_address[addr]
            )
        )

    return instrumented


parser = argparse.ArgumentParser(
    prog="lockfree_tester", description="lockfree_tester runner"
)
parser.add_argument("test_executable", help="Path to the test executable")
parser.add_argument(
    "-c",
    "--collect_dir",
    default="./collect",
    help="Directory which will contain collected instrumentation data",
)
parser.add_argument(
    "--dynamorio_dir", default="./DynamoRIO", help="`DynamoRIO` installation directory"
)
parser.add_argument(
    "--dynamorio_clients_dir",
    default="./build/src",
    help="Directory which contains `libcollector.so` and `librunner.so`",
)
parser.add_argument(
    "-t",
    "--trace",
    action="store_true",
    default=False,
    help="Enable tracing output. Same as setting both `--trace_test and `--trace_runner`",
)
parser.add_argument(
    "--trace_test",
    action="store_true",
    default=False,
    help="Enable tracing output for the test program",
)
parser.add_argument(
    "--trace_runner",
    action="store_true",
    default=False,
    help="Enable tracing output the test runner",
)
args = parser.parse_args()
if args.trace:
    args.trace_test = True
    args.trace_runner = True

INSTRUCTIONS_PATH = os.path.join(args.collect_dir, "instructions.bin")
EXIT_PATH = os.path.join(args.collect_dir, "exit")

print("Deleting", args.collect_dir, "...")
shutil.rmtree(args.collect_dir, ignore_errors=True)
os.makedirs(args.collect_dir)

print("Collecting...")
run_command(
    os.path.join(args.dynamorio_dir, "bin64/drrun"),
    "-c",
    os.path.join(args.dynamorio_clients_dir, "libcollector.so"),
    "--",
    args.test_executable,
    silent_errors=True,
)

print("Determining instructions...")
instrumented = get_instructions_to_instrument(args.collect_dir)

print("Creating", INSTRUCTIONS_PATH, "...")
with open(INSTRUCTIONS_PATH, "wb") as f:
    write_packed_int64(f, len(instrumented))
    for instr in instrumented:
        write_packed_string(f, instr.module.path)
        write_packed_int64(f, instr.offset)
        write_packed_bool8(f, instr.name == "syscall")
        write_packed_int64(f, instr.access_count1)
        write_packed_int64(f, instr.access_count2)

print("Instrumented instruction count:", len(instrumented))
# exit(0)

# Run the tests and periodically check if `EXIT_PATH` exists, in which case terminate the process.
print("Running tests...")
cmds = [
    os.path.join(args.dynamorio_dir, "bin64/drrun"),
    "-opt_cleancall",
    "2",
    "-opt_speed",
    "-c",
    os.path.join(args.dynamorio_clients_dir, "librunner.so"),
    "--instructions_file",
    INSTRUCTIONS_PATH,
    "--exit_file",
    EXIT_PATH,
    "--trace" if args.trace_runner else "",
    "--",
    args.test_executable,
]
print(" ".join(cmds))

with subprocess.Popen(cmds) as process:
    atexit.register(kill_process_and_descendants, process)

    def check_deadlock(process):
        while True:
            time.sleep(1)
            if os.path.exists(EXIT_PATH):
                kill_process_and_descendants(process)
                return

    threading.Thread(target=check_deadlock, args=(process,), daemon=True).start()
    process.wait()

print("All done!")
print(" ".join(cmds))
