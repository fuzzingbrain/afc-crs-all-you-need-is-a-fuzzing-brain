#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "json.h"
#include "base64.h"
#include "utils.h"
#include "netutils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  json_value *obj;
  obj = json_parse(data, size);
  if (obj == NULL) {
    return 0;
  }
  json_value_free(obj);

  char *ns = malloc(size+1);
  memcpy(ns, data, size);
  ns[size] = '\0';

  ss_isnumeric(ns);

  validate_hostname(ns, size);

  free(ns);
  return 0;
}
