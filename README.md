# Concurrency Testing Framework

This is an experimental framework for testing concurrent programs.

At a high level, it runs tests many times, permuting the possible concurrent executions of each test in order to find traces which would cause the test to fail. The framework is language-agnostic, and can test any program which compiles down to a binary. I developed it as a part of my master's thesis.

The key features are:
- Exhaustively tests all possible thread scheduling orders that could impact the final result.
- Reproduces discovered bugs deterministically with the same thread schedule.
- Tests existing code without requiring any source modifications.
- Supports testing highly optimized release builds.
- Language agnostic, can test programs in any language that compile down to a native binary (C, C++, Go, Rust, D, etc...).

## Table of Contents

- [Concurrency Testing Framework](#concurrency-testing-framework)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Example: Testing an SPSC Queue](#example-testing-an-spsc-queue)
    - [Sample Output](#sample-output)
  - [Building](#building)
    - [Prerequisites](#prerequisites)
    - [Building DynamoRIO (optional)](#building-dynamorio-optional)
    - [Building the Framework](#building-the-framework)
  - [Writing Tests](#writing-tests)
    - [Test Structure Template](#test-structure-template)
  - [Running Tests](#running-tests)
    - [Provided examples](#provided-examples)
  - [Limitations and Future Work](#limitations-and-future-work)
  - [Adding Support for Other Languages](#adding-support-for-other-languages)
    - [Rust](#rust)
      - [Overview](#overview-1)
      - [Example Implementation](#example-implementation)
      - [Using the Rust Test Tools in a Test](#using-the-rust-test-tools-in-a-test)
    - [Running the Tests](#running-the-tests)
  - [License](#license)

## Overview

Testing concurrent programs is challenging; threads can interleave in all sorts of ways, and each interleaving might expose a hidden concurrency bug in your program. Some bugs are so rare that they only occur under a very small set of possible executions, and may not surface even if you run the code millions or billions of times.

Concurrency Bug Finder provides a way to deterministically explore all possible thread scheduling orders without relying on random chance. This allows you to write tests that verify your concurrent code is correct under all executions, not just "most of the time".

The testing is done in three main steps:

1. Tracing: The test program is executed normally while recording information about executed instructions, such as the type and address of each instruction, the thread executing it, and the memory locations it reads from or writes to.

2. Analysis: The collected data is analyzed to determine which instructions represent serialization points and how many times each thread executes them.

3. Serialized Execution: The test is run many times, trying out all possible thread schedules one by one. This is achieved by injecting code before each instruction identified in the analysis step. When a thread reaches a serialization point, it decides whether to continue executing or yield control to another thread.

The framework's two key advantages compared to similar tools are:

1. Is the ability to test existing code without modifications, even if you don't have access to the source (like a precompiled library).
2. Testing highly optimized release builds, which have more opportunities for presenting unexpected race conditions due to compiler optimizations.

## Example: Testing an SPSC Queue

Below is a complete test program for a Single Producer Single Consumer (SPSC) FIFO queue. The queue can hold up to two elements. In this test, we deliberately try to push three elements to check how the queue handles overflow.

The test program is a standard C++ program that spawns a consumer and a producer thread. It calls some framework-specific functions like `RunStart()` and `RunEnd()` in order to mark which regions of the code need to be instrumented. Do note that the actual queue implementation doesn't have to be modified at all in order to be tested.

```cpp
#include <atomic>
#include <cstdint>
#include <thread>
#include "test_tools.h"

// Queue implementation omitted for brevity. Assume a standard FIFO circular
// buffer implementation.
template <typename T, size_t size>
class Queue {
 public:
  bool Push(const T &element);
  bool Pop(T &element);

 private:
  std::atomic<size_t> r_{};
  std::atomic<size_t> w_{};
  T data_[size]{};
}

using QueueT = Queue<int, 3>;

void producer(QueueT& q) {
  int thread_id = RegisterThread();
  while (Testing()) {
    // Reset the queue
    q.~QueueT();
    new (&q) QueueT();

    RunStart();

    bool push1 = q.Push(PreventOpt(1));
    bool push2 = q.Push(PreventOpt(2));
    // push3 might fail because the queue can hold at most 2 elements.
    bool push3 = q.Push(PreventOpt(3));

    AssertAlways(push1 && push2);
    // This assertion is incorrect! push3 might not always succeed.
    AssertAlways(push3);

    RunEnd();
  }
}

void consumer(QueueT& q) {
  int thread_id = RegisterThread();
  while (Testing()) {
    RunStart();

    int value;

    // Any pop might fail if the queue is empty.
    bool pop1 = q.Pop(value);
    AssertAlways(!pop1 || (value > 0 && value == 1));

    bool pop2 = q.Pop(value);
    AssertAlways(!pop2 || (value > 0 && value <= 2));

    bool pop3 = q.Pop(value);
    AssertAlways(!pop3 || (value > 0 && value <= 3));

    RunEnd();
  }
}

int main() {
  QueueT q;
  std::thread t1(producer, std::ref(q));
  std::thread t2(consumer, std::ref(q));
  t1.join();
  t2.join();
  return 0;
}
```

**Explanation:**

- **Producer Thread:**
  - Tries to push three elements into the queue.
  - The queue can only hold two elements, so `push3` might fail.
  - The assertion `AssertAlways(push3)` is incorrect because `push3` doesn't always succeed.

- **Consumer Thread:**
  - Attempts to pop three elements from the queue.
  - Each pop operation checks if it succeeded and validates the value.

When running this test through the framework, it will explore all possible thread interleavings. It will find the schedule where the producer tries to push the third element when the queue is full, causing `push3` to fail and the assertion to fail. The framework will report this, providing an execution history to help you identify and fix the issue.

### Sample Output

When an assertion fails, the framework provides a detailed execution history:

```
< T1: going to sleep before executing 0x4014d0 (mov)
        > T2: will execute 0x401510 (mov)
        > T2: will execute 0x401514 (mov)
        > T2: will execute 0x401510 (mov)
        > T2: will execute 0x401514 (mov)
        > T2: will execute 0x401510 (mov)
        > T2: will execute 0x401514 (mov)
        < T2: completed the test!
> T1: will execute 0x4014d0 (mov)
> T1: will execute 0x4014d9 (mov)
> T1: will execute 0x4014f0 (mov)
> T1: will execute 0x4014f8 (mov)
> T1: will execute 0x4014d0 (mov)
> T1: will execute 0x4014d9 (mov)
> T1: will execute 0x4014f0 (mov)
> T1: will execute 0x4014f8 (mov)
> T1: will execute 0x4014d0 (mov)
> T1: will execute 0x4014d9 (mov)
< T1: ASSERTION FAILED!

!!! Some assertions failed for the test permutation: 0xfcr3ef
```

You can then re-run the test (and attach a debugger) with this specific execution history to reproduce and debug the issue:
```
python tools/run.py --permutation 0xfcr3ef my_test_program
```

## Building

### Prerequisites

Make sure you have the following dependencies installed:
- cmake
- Clang++ with C++20 support or newer
- Python 3.10 or newer
- DynamoRIO version `10.0.0` or newer, or if building DynamoRIO from source (recommended), all dependencies required by [DynamoRIO](https://dynamorio.org/page_building.html)

### Building DynamoRIO (optional)

While you can install DynamoRIO using your system's package manager, I recommend building it from source using the provided `build_dynamorio.sh` script to ensure you have at least version 10.0.0.

To build DynamoRIO, simply run:
```
./build_dynamorio.sh
```

For additional debug output during instrumentation, build with:
```
./build_dynamorio.sh -DDEBUG=ON
```

### Building the Framework

Once DynamoRIO is built, you can build the testing framework:

```
cmake -Bbuild -DCMAKE_INSTALL_PREFIX=DynamoRIO .
cmake --build build -j
```

If you want to use your system's DynamoRIO installation just omit the `CMAKE_INSTALL_PREFIX`:
```
cmake -Bbuild .
cmake --build build -j
```

The compiled files used by the framework will be in `build/src`, and example tests are in `build/example`.

## Writing Tests

To test your data structure or algorithm, you need to write a test program using functions defined in `src/test_tools/test_tools.h`. Your test program is a standalone executable and doesn't depend on the testing framework during compilation. When running through the framework, calls to these functions are replaced with appropriate implementations to facilitate the testing process.

### Test Structure Template

```cpp
#include <thread>
#include "test_tools.h"

void test() {
  int thread_id = RegisterThread();

  while (Testing()) {
    // Initialization code before calling `RunStart()`.

    RunStart();
    // Test code between `RunStart()` and `RunEnd()`.
    // Example: `AssertAlways(condition)`;

    RunEnd();
  }
}

int main() {
  std::thread t1(test);
  std::thread t2(test);
  t1.join();
  t2.join();
  return 0;
}
```

**Function Overview:**

- `RegisterThread()`: Registers the calling thread with the framework. Returns a thread ID.
- `Testing()`: Returns `true` if the framework is still testing different thread schedules.
- `RunStart()`: Synchronization point before the test code. All threads reach this point before proceeding.
- `RunEnd()`: Marks the end of the test code for the current iteration.
- `PreventOpt(value)`: Prevents the compiler from optimizing away a variable or value. As a rule of thumb, always wrap literal values in your tests to prevent whole sections of your test from being optimized away when compiling with `-O2` or higher.
- `AssertAlways(condition)`: Asserts that `condition` must be true in every possible thread schedule.
- `AssertAtleastOnce(condition_key, condition)`: Asserts that there exists at least one thread schedule where `condition` is true.

## Running Tests

To run a test:
```
python tools/run.py <path_to_test_executable>
```

For more options:
```
python tools/run.py --help
```

### Provided examples

The `example` directory contains a few different tests which test lock-free data structures from a few different libraries. In order to compile them build the project with the `BUILD_EXAMPLES` flag:
```
cmake -Bbuild -DCMAKE_INSTALL_PREFIX=DynamoRIO -DBUILD_EXAMPLES=ON .
cmake --build build -j
```
Note that the examples might depend on various libraries like Boost.

To run the premade examples do:
```
python tools/run.py build/example/<example_test>
```

## Limitations and Future Work

While this framework improves upon existing solutions in a number of ways, it still has some (large) limitations:

- The instrumentation step may miss instructions that access shared memory depending on the thread schedule. I mitigate this by repeating instrumentation many times with random delays, but a more robust solution would be to perform static analysis on the machine code. Unfortunately I didn't have enough time during my thesis in order to implement or even experiment with this.

- It does not model the processor's memory model or the memory ordering of atomic operations. Ideally, the framework would be extended to take these into account. If this is something you require, check out [C11Tester](https://github.com/c11tester).

- The number of possible thread interleavings grows exponentially with the number of threads, limiting the complexity of tests. Techniques like symmetry reduction and partial order reduction could help prune the state space. A similar tool for Rust which implements partial state reduction is [loom](https://docs.rs/loom/latest/loom/).

- The framework does not currently support critical sections. Intercepting system calls like futex could allow transferring control from a blocked thread to a free one, enabling testing of various synchronization primitives.

Despite these limitations, I believe this framework provides a valuable tool for testing lock-free algorithms and uncovering subtle concurrency bugs. If you want to contribute, have any ideas for improvements, or need any help with the tool, feel free to reach out.

## Adding Support for Other Languages

I designed the testing framework to be language-agnostic, allowing it to test lock-free algorithms written in languages other than C or C++. The key requirement is to reimplement the `test_tools.h` functionality in your target language. This involves creating stub functions (empty symbols) with specific names and preventing the compiler from applying optimizations that could interfere with the testing process.

### Rust

To illustrate how to add support for another language, here's how you can implement the `test_tools` functionality in Rust.

#### Overview

In C/C++, the `test_tools.h` file declares functions that:

- Have specific names recognized by the testing framework.
- Are marked to prevent inlining and other compiler optimizations.
- Include memory fences to prevent instruction reordering around function calls.

In Rust, we need to achieve the same goals. This involves:

- Defining functions with exact names expected by the framework.
- Using attributes and constructs to prevent compiler optimizations.
- Ensuring memory fences are placed correctly.

#### Example Implementation

Below is an example of how to create the necessary stub functions in Rust:

```rust
use std::sync::atomic::{compiler_fence, Ordering};

/// Prevents the compiler from optimizing away reads and writes.
#[inline(never)]
pub fn compiler_barrier() {
    compiler_fence(Ordering::SeqCst);
}

/// Prevents the compiler from optimizing away a value.
pub fn prevent_opt<T>(x: T) -> T {
    compiler_barrier();
    let ret = unsafe { std::ptr::read_volatile(&x) };
    compiler_barrier();
    ret
}

/// Macro to wrap expressions with compiler fences.
macro_rules! fence_wrapper {
    ($expr:expr) => {{
        compiler_barrier();
        let ret = $expr;
        compiler_barrier();
        ret
    }};
}

/// Define stub functions with exact names.

#[no_mangle]
pub extern "C" fn _Tracing() -> bool {
    false
}

#[no_mangle]
pub extern "C" fn _Instrumenting() -> bool {
    false
}

#[no_mangle]
pub extern "C" fn _InstrumentationPause() {
    // Empty stub function
}

//
// ... Do this for all the other functions in `test_tools.h`.
//

/// Wrapper functions that can be used in test code.

pub fn Tracing() -> bool {
    fence_wrapper!(_Tracing())
}

pub fn Instrumenting() -> bool {
    fence_wrapper!(_Instrumenting())
}

pub fn InstrumentationPause() {
    fence_wrapper!(_InstrumentationPause())
}

//
// ... Do this for all the other functions in `test_tools.h`.
//
```

#### Using the Rust Test Tools in a Test

With `test_tools` implemented in Rust, you can write your test code as follows:

```rust
use std::thread;

mod test_tools; // Assuming the above code is in test_tools.rs

use test_tools::*;

fn test() {
    let thread_id = RegisterThread();

    while Testing() {
        // Initialization code before RunStart()

        RunStart();

        // Test code between RunStart() and RunEnd()
        // Example assertion
        AssertAlways(true);

        RunEnd();
    }
}

fn main() {
    let t1 = thread::spawn(test);
    let t2 = thread::spawn(test);

    t1.join().unwrap();
    t2.join().unwrap();
}
```

### Running the Tests

After implementing `test_tools` in Rust, you can compile your test program as usual. When running the test through the framework, it will intercept and replace the stub functions you've defined, allowing it to control thread execution and collect execution data.

**Example Command to Run the Test:**

```bash
python tools/run.py target/release/your_rust_test_executable
```

Replace `target/release/your_rust_test_executable` with the path to your compiled Rust test executable.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
