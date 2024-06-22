# Building

## Building DynamoRIO

It's recommended to install `DynamoRIO` by using the following script. It's possible to install `DynamoRIO` with your system's package manager, however it is not advised. If you decide to use your system's package manager make sure that the `DynamoRIO` version is at least `10.0.0`.

Before running the script make sure to install all prerequisites required by `DynamoRIO`, listed on their [repository page](https://github.com/DynamoRIO/dynamorio):
```
cmake g++ g++-multilib doxygen git zlib1g-dev libunwind-dev libsnappy-dev liblz4-dev
```

To build `DynamoRIO` run the following script:
```
./build_dynamorio.sh
```
To enable additional debug output for the instrumentation build `DynamoRIO` in debug mode:
```
./build_dynamorio.sh -DDEBUG=ON
```

## Building the app

Then build the project:
```
cmake -Bbuild -DCMAKE_INSTALL_PREFIX=DynamoRIO .
cmake --build build -j
```
If you are using your system's `DynamoRIO` installation, simply omit the `CMAKE_INSTALL_PREFIX` argument:
```
cmake -Bbuild -DCMAKE_INSTALL_PREFIX=DynamoRIO .
cmake --build build -j
```

The built program will be in `build/src`, and the examples which you can run try are in `build/example`.

# Running a test

Run all commands from the repository's root directory.

Run a test:
```
python tools/run.py <path_to_test_executable>
```
For more options run:
```
python tools/run.py --help
```

# Common helpers

Disassemble a test:
```
objdump -C -M intel -d build/example/lockfree/spsc_queue > disassm.txt
```
