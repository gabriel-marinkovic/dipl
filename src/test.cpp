#include <iostream>

#include "dr_api.h"
#include "dr_tools.h"

#include "common.h"

namespace app {

void entry() {
	void* drcontext = dr_standalone_init();

  const char* path = "/home/gabriel/dipl/temp/foo.bin";
  file_t file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
  DR_ASSERT(file != INVALID_FILE);

  BufferedFileWriter writer;
  BufferedFileWriter::Make(&writer, drcontext, file, 53);

  for (uint32_t i = 0; i < 100; ++i) {
  	writer.WriteUint32LE(i);
  }

  writer.FlushAndDestroy();

  file = dr_open_file(path, DR_FILE_READ | DR_FILE_ALLOW_LARGE);
  DR_ASSERT(file != INVALID_FILE);

  BufferedFileReader reader;
  BufferedFileReader::Make(&reader, drcontext, file, 28);

  uint32_t value;
  while (reader.ReadUint32LE(&value)) {
  	std::cout << value << std::endl;
  }

  reader.Destroy();
}

}  // namespace app

int main() {
  app::entry();
  return 0;
}
