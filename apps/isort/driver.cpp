#include <cstdint>
#include <cstring>

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

extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  TYPE *tmp = new TYPE[Size];
  memcpy(tmp, Data, Size);

  isort(tmp, Size / sizeof(TYPE));

  delete[] tmp;
  return 0;
}


