#include <Windows.h>


unsigned long main_thread(void* trash) {
    MessageBox(0, "Test", "Mapper Test", 0);

    return 0;
}

bool DllMain(void* lp_reserved) {

    if (void* thread_handle = CreateThread(nullptr, 0, main_thread, 0, 0, nullptr))
        CloseHandle(thread_handle);

    return true;
}
