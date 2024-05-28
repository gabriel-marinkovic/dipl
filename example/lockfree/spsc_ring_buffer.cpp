#include <cstdint>
#include <cstring>
#include <thread>
#include <stdio.h>
#include "lockfree.hpp"
#include "test_tools.h"

constexpr int RINGSIZE = 3;
using RingBufT = lockfree::spsc::RingBuf<uint32_t, RINGSIZE>;

void producer(RingBufT& rb) {
    int thread_id = RegisterThread(0);

    while (Testing()) {
        rb.~RingBufT();
        new (&rb) RingBufT();

        RunStart();

        uint32_t data1[] = {1};
        uint32_t data2[] = {2};
        uint32_t data3[] = {3};

        bool write1 = rb.Write(PreventOpt(data1), 1);
        bool write2 = rb.Write(PreventOpt(data2), 1);
        bool write3 = rb.Write(PreventOpt(data3), 1);

        AssertAlways(write1 && write2);
        AssertAtleastOnce(0, !write3);
        AssertAtleastOnce(1, write3);
        RunEnd();
    }
}

void consumer(RingBufT& rb) {
    int thread_id = RegisterThread(1);

    while (Testing()) {
        RunStart();

        bool ok = true;
        uint32_t value = 0xff;
        bool read;

        read = rb.Read(&value, 1);
        ok = ok && (!read || (value != 0 && value == 1));

        read = rb.Read(&value, 1);
        ok = ok && (!read || (value != 0 && value <= 2));

        read = rb.Read(&value, 1);
        ok = ok && (!read || (value != 0 && value <= 3));

        AssertAlways(ok);
        AssertAtleastOnce(2, !read);
        AssertAtleastOnce(3, read && value == 3);
        RunEnd();
    }
}

int main() {
    RingBufT rb;
    std::thread t1(producer, std::ref(rb));
    std::thread t2(consumer, std::ref(rb));

    t1.join();
    t2.join();
    return 0;
}
