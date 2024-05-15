# Building

First, build `DynamoRIO`:
```
./build_dynamorio.sh
```
Or in debug mode:
```
./build_dynamorio.sh -DDEBUG=ON
```

Then build the project:
```
cmake -Bbuild -DCMAKE_INSTALL_PREFIX=DynamoRIO .
cmake --build build -j
```


# Running a test

To run a test stored in `example` run:
```
python tools/run.py
```
To change which test to run edit the `APP_UNDER_TEST` path in `tools/run.py`.


# Common helpers

Disassemble a test:
```
objdump -C -M intel -d build/example/lockfree/spsc_queue > disassm.txt
```

Kill ghost processes:
```
killall -s SIGKILL spsc_queue
```
