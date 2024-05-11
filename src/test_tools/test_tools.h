#define TEST_TOOL_FUNCTION __attribute__((noinline, used))

extern "C" {

bool TEST_TOOL_FUNCTION Instrumenting();
void TEST_TOOL_FUNCTION InstrumentationPause();
void TEST_TOOL_FUNCTION InstrumentationResume();
void TEST_TOOL_FUNCTION InstrumentingWaitForAll();

bool TEST_TOOL_FUNCTION NextRun();
void TEST_TOOL_FUNCTION RunDone();
int TEST_TOOL_FUNCTION ThreadIdx();
void TEST_TOOL_FUNCTION MustAlways(bool ok);
void TEST_TOOL_FUNCTION MustAtleastOnce(bool ok);

}

