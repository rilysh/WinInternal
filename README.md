# WinInternal

WinInternal is a header only file which you can include in your project and can do internal works of Windows.

# Basic

This header file contains some basic operations you just need to call them in right time.

# Example

```cpp
#include "wininternal.h"
int main()
{
  WININTRNL::INTERNAL Internal;
  Internal.RegCreateSet(HKEY_CURRENT_USER, "Test", "Simple", REG_SZ, "Data is simple", 15);
  return 0;
}
```

# Help

If you find any problems with any project just join our Discord server. We will help you!
