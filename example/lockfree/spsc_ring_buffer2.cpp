#include <cstring>
#include <cstdint>
#include <thread>
#include <iostream>
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
        ContiguousMemoryHint(&rb, sizeof(rb));

        uint32_t data1[] = {1, 2};
        uint32_t data2[] = {3, 4};
        uint32_t data3[] = {5, 6};

        bool write1 = rb.Write(PreventOpt(data1), 2);
        TRACE(std::cout << "Write1: " << write1 << std::endl);
        bool write2 = rb.Write(PreventOpt(data2), 2);
        TRACE(std::cout << "Write2: " << write2 << std::endl);
        bool write3 = rb.Write(PreventOpt(data3), 2);
        TRACE(std::cout << "Write3: " << write3 << std::endl);

        AssertAlways(write1);
        AssertAtleastOnce(0, !write2);
        AssertAtleastOnce(1, write2);
        AssertAtleastOnce(2, !write3);
        AssertAtleastOnce(3, write3);
        RunEnd();
    }
}

void consumer(RingBufT& rb) {
    int thread_id = RegisterThread(1);

    while (Testing()) {
        RunStart();

        bool ok = true;
        uint32_t values[2] = {0xff, 0xff};
        bool read;

        read = rb.Read(values, 2);
        ok = ok && (!read || (values[0] == 1 && values[1] == 2));

        read = rb.Read(values, 2);
        ok = ok && (!read || (values[0] == 3 && values[1] == 4));

        read = rb.Read(values, 2);
        ok = ok && (!read || (values[0] == 5 && values[1] == 6));

        AssertAlways(ok);
        AssertAtleastOnce(4, !read);
        AssertAtleastOnce(5, read && values[0] == 5 && values[1] == 6);
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
