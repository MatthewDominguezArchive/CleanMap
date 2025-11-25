# CleanMap
User mode manual mapper with no shellcode.

## Features:
- Single header include
- Load from file path / byte array.
- No shellcode
- No tls callbacks

## How to use:
### Include like this:
```cpp
#include "mapper.h"
```

### Call like this:
```cpp
mapper::map_from_file_path(dll_name, target_name)
```
or like this (meow is a std::unique_ptr<char[]> containing the dll)
```cpp
mapper::map_from_byte_array(meow, size, target_name)
```

### Your DLL entry point:
```cpp
unsigned long main_thread(void* trash)
```

![before](https://pasteboard.co/hirgP5Zpmc8A.png)

![after](https://pasteboard.co/9OABMVxLrWpV.png)
