#include <stdint.h>
#include <stddef.h>

#include "vuln.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    person_info_t person;
    person_info_parse_file(&person, (const char *)data);
    return 0;
}