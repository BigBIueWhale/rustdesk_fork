// Native reproduction of the pinned libyuv arithmetic findings. Not an app test.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <vector>

#include "libyuv/row.h"
#include "libyuv/scale.h"

template <typename T, typename Scale>
int scale_case(Scale scale, int height) {
  // Every sample the valid operation may read is allocated, including the
  // oversized case. A buffer overrun in this fixture cannot explain SIGFPE.
  const int rows = height < 0 ? -height : height;
  std::vector<T> source(rows, 55);
  T destination = 0;
  scale(source.data(), 1, 1, height, &destination, 1, 1, 1,
        libyuv::kFilterNone);
  if (destination != 55) return 80;
  std::puts("pixels=exact");
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 3) return 81;
  if (std::strcmp(argv[1], "affine") == 0) {
    alignas(uint32_t) uint8_t destination[4] = {};
    const uint8_t expected[4] = {19, 37, 71, 255};
    float coordinates[4] = {0, 0, 0, 0};
    if (std::strcmp(argv[2], "small") == 0) {
      alignas(uint32_t) uint8_t source[4];
      std::memcpy(source, expected, 4);
      libyuv::ARGBAffineRow_C(source, 4, destination, coordinates, 1);
    } else if (std::strcmp(argv[2], "large-stride") == 0) {
      // Reserve virtual address space, committing only one page. The valid
      // source pixel lies at offset 2 GiB; no multi-gigabyte data is allocated.
      const size_t offset = size_t{1} << 31;
      const size_t length = offset + 4096;
      void* mapping = mmap(nullptr, length, PROT_NONE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (mapping == MAP_FAILED) return 82;
      auto source = static_cast<uint8_t*>(mapping);
      if (mprotect(source + offset, 4096, PROT_READ | PROT_WRITE) != 0) return 83;
      std::memcpy(source + offset, expected, 4);
      coordinates[1] = 2;
      libyuv::ARGBAffineRow_C(source, 1 << 30, destination, coordinates, 1);
      if (munmap(mapping, length) != 0) return 84;
    } else {
      return 85;
    }
    if (std::memcmp(destination, expected, 4) != 0) return 86;
    std::puts("pixels=exact");
    return 0;
  }
  int height;
  if (std::strcmp(argv[2], "copy") == 0) height = 1;
  else if (std::strcmp(argv[2], "downscale") == 0) height = 2;
  else if (std::strcmp(argv[2], "inverted") == 0) height = -2;
  else if (std::strcmp(argv[2], "boundary") == 0) height = 32768;
  else if (std::strcmp(argv[2], "oversize") == 0) height = 32769;
  else return 87;
  if (std::strcmp(argv[1], "8") == 0)
    return scale_case<uint8_t>(libyuv::ScalePlane, height);
  if (std::strcmp(argv[1], "16") == 0)
    return scale_case<uint16_t>(libyuv::ScalePlane_16, height);
  if (std::strcmp(argv[1], "12") == 0)
    return scale_case<uint16_t>(libyuv::ScalePlane_12, height);
  return 88;
}
