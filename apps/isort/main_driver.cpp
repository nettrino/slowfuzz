#include <cstdint>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define TYPE uint8_t

using namespace std;

void isort(TYPE *arr, int n) {
	for (int i = 0; i < n; i++) {
		for (int c = i - 1; c >= 0; c--) {
			if (arr[c] > arr[c + 1]) {
				TYPE temp = arr[c];
				arr[c] = arr[c + 1];
				arr[c + 1] = temp;
			}
			else
				break;
		}
	}
}

static int read_file(const char *fn, unsigned char **buf)
{
    struct stat file_status;
    FILE *fp;
    int ret = -1;

    if ((stat(fn, &file_status) != 0) ||
        ((fp = fopen(fn, "r")) == NULL) ||
        ((*buf = (unsigned char *)malloc(file_status.st_size)) == NULL)) {
        perror("read_file"); \
        return -1;
    }

    if (!fread(*buf, file_status.st_size, 1, fp)) {
        perror("read_file");
        free(*buf);
    } else {
        ret = file_status.st_size;
    }

    fclose(fp);
    return ret;
}

int main(int argc, char *argv[])
{
	uint8_t *data;
	size_t size = read_file(argv[1], &data);

  TYPE *tmp = new TYPE[size];
  memcpy(tmp, data, size);

  isort(tmp, size / sizeof(TYPE));

  delete[] tmp;
  free(data);
  return 0;
}

#if 0
extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  TYPE *tmp = new TYPE[Size];
  memcpy(tmp, Data, Size);

  isort(tmp, Size / sizeof(TYPE));

  delete[] tmp;
  return 0;
}
#endif
