#include <Windows.h>
#include <fstream>
#include <string>
#include <string_view>
#include <tlhelp32.h>
#include <vector>
#include <winternl.h>


#define PRINT_NONE 2
#define PRINT_NORMAL 1
#define PRINT_ALL 0

namespace mapper
{
    inline void* target_handle{};

    inline char print_type = PRINT_ALL;

    struct dll
    {
        std::unique_ptr<char[]> buffer;
        std::uintptr_t size;
        IMAGE_DOS_HEADER* dos_header;
        IMAGE_NT_HEADERS64* nt_headers;
        IMAGE_OPTIONAL_HEADER64 optional_header;

        dll(std::uintptr_t size) : size(size)
        {
            this->buffer = std::make_unique<char[]>(size);
        }

        void populate_headers()
        {
            this->dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(this->buffer.get());
            this->nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(this->buffer.get() + this->dos_header->e_lfanew);
            this->optional_header = this->nt_headers->OptionalHeader;
        }
    };

    inline bool get_process_handle(std::string_view& target_name)
    {
        void* snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(snapshot, &pe))
        {
            return false;
        }
        do
        {
            if (_stricmp(pe.szExeFile, target_name.data()) == 0)
            {
                target_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pe.th32ProcessID);
                if (!target_handle)
                {
                    return false;
                }
                CloseHandle(snapshot);
                break;
            }
        } while (Process32Next(snapshot, &pe));

        if (target_handle == nullptr)
        {
            return false;
        }

        return true;
    }

    inline bool allocate_dll_space(std::size_t size, void*& allocated_base)
    {
        allocated_base = VirtualAllocEx(target_handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!allocated_base)
        {
            return false;
        }

        return true;
    }

    inline void create_virtual_dll(dll& phys, dll& virt)
    {
        // Copy all headers
        std::memcpy(virt.buffer.get(), phys.buffer.get(), phys.nt_headers->OptionalHeader.SizeOfHeaders);

        virt.populate_headers();

        IMAGE_SECTION_HEADER* phys_section_table = IMAGE_FIRST_SECTION(phys.nt_headers);
        auto virt_section_table = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                reinterpret_cast<char*>(&virt.nt_headers->OptionalHeader) + virt.nt_headers->FileHeader.SizeOfOptionalHeader
        );

        for (auto section_index = 0; section_index < virt.nt_headers->FileHeader.NumberOfSections; section_index++)
        {
            // Copy sections into their "Loaded" location in the virt dll.
            auto section_size = phys_section_table[section_index].SizeOfRawData;

            auto from_addr = phys.buffer.get() + phys_section_table[section_index].PointerToRawData;

            auto to_addr = virt.buffer.get() + virt_section_table[section_index].VirtualAddress;

            memcpy(reinterpret_cast<void*>(to_addr), reinterpret_cast<void*>(from_addr), section_size);
        }
    }

    inline void handle_relocations(dll& virt, void*& allocated_base)
    {

        auto reloc_directory = virt.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        auto reloc_section_start = reinterpret_cast<char*>(virt.buffer.get() + reloc_directory.VirtualAddress);
        auto block_cursor = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reloc_section_start);

        while (reinterpret_cast<std::uintptr_t>(block_cursor) < reinterpret_cast<std::uintptr_t>(reloc_section_start + reloc_directory.Size))
        {
            auto entry_cursor = (reinterpret_cast<unsigned short*>(block_cursor + 1));
            for (; reinterpret_cast<std::uintptr_t>(entry_cursor) <
                   reinterpret_cast<std::uintptr_t>(reinterpret_cast<char*>(block_cursor) + block_cursor->SizeOfBlock);
                 entry_cursor++)
            {
                auto rva = block_cursor->VirtualAddress + (*entry_cursor & 0xFFF);
                auto target = reinterpret_cast<std::uintptr_t*>(virt.buffer.get() + rva);
                *target += reinterpret_cast<std::intptr_t>(allocated_base) - virt.optional_header.ImageBase;
            }
            block_cursor = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<char*>(block_cursor) + block_cursor->SizeOfBlock);
        }
    }

    // Probably not to be used in real life, but good for testing.
    inline bool load_missing_dll(std::string import_dll_name_str)
    {
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (!kernel32)
        {
            return false;
        }

        std::vector<wchar_t> raw_full_dll_path(MAX_PATH);

        unsigned long search_path_result = SearchPathW(
                nullptr, std::wstring(import_dll_name_str.begin(), import_dll_name_str.end()).c_str(), nullptr, raw_full_dll_path.size(),
                raw_full_dll_path.data(), nullptr
        );

        if (!search_path_result)
        {
            return false;
        }

        if (search_path_result > raw_full_dll_path.size())
        {
            raw_full_dll_path.resize(search_path_result);
            search_path_result = SearchPathW(
                    nullptr, std::wstring(import_dll_name_str.begin(), import_dll_name_str.end()).c_str(), nullptr, raw_full_dll_path.size(),
                    raw_full_dll_path.data(), nullptr
            );
        }

        auto wide_full_dll_path = std::wstring(raw_full_dll_path.data());

        auto full_dll_path = std::string(wide_full_dll_path.begin(), wide_full_dll_path.end());

        LPVOID allocMem = VirtualAllocEx(target_handle, NULL, strlen(full_dll_path.c_str()) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!allocMem)
        {
            return false;
        }

        if (!WriteProcessMemory(target_handle, allocMem, full_dll_path.c_str(), strlen(full_dll_path.c_str()) + 1, NULL))
        {
            return false;
        }

        HANDLE thread = CreateRemoteThread(
                target_handle, NULL, 0, (LPTHREAD_START_ROUTINE)(LPVOID)GetProcAddress(kernel32, "LoadLibraryA"), allocMem, 0, NULL
        );

        if (!thread)
        {
            return false;
        }

        WaitForSingleObject(thread, INFINITE);

        VirtualFreeEx(target_handle, allocMem, 0, MEM_RELEASE);
        CloseHandle(thread);

        return true;
    }

    inline bool fix_imports(dll& virt)
    {
        auto import_section = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                virt.buffer.get() + virt.optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );

        PROCESS_BASIC_INFORMATION pib{};
        if (!NT_SUCCESS(NtQueryInformationProcess(target_handle, ProcessBasicInformation, &pib, sizeof(PROCESS_BASIC_INFORMATION), nullptr)))
        {
            return false;
        }

        PEB pleb;
        ReadProcessMemory(target_handle, pib.PebBaseAddress, &pleb, sizeof(PEB), nullptr);

        PEB_LDR_DATA ldr;
        ReadProcessMemory(target_handle, pleb.Ldr, &ldr, sizeof(PEB_LDR_DATA), nullptr);

        for (; import_section->Name; import_section++)
        {
            auto import_dll_name = reinterpret_cast<char*>(virt.buffer.get() + import_section->Name);

            auto iat_cursor = reinterpret_cast<IMAGE_THUNK_DATA*>(virt.buffer.get() + import_section->FirstThunk);
            auto int_cursor = reinterpret_cast<IMAGE_THUNK_DATA*>(virt.buffer.get() + import_section->OriginalFirstThunk);

            auto load_library = LoadLibrary(import_dll_name);

            bool found_dll{};

            for (; int_cursor->u1.AddressOfData; int_cursor++, iat_cursor++)
            {
                auto func_name =
                        reinterpret_cast<char*>(reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(virt.buffer.get() + int_cursor->u1.AddressOfData)->Name);
                auto func_add = reinterpret_cast<std::uintptr_t>(virt.buffer.get() + iat_cursor->u1.AddressOfData);

                auto proc_offset =
                        reinterpret_cast<std::uintptr_t>(GetProcAddress(load_library, func_name)) - reinterpret_cast<std::uintptr_t>(load_library);


                LIST_ENTRY* first_flink = ldr.InMemoryOrderModuleList.Flink;
                LIST_ENTRY* current_flink = first_flink;

                do
                {
                    std::uintptr_t entry_address =
                            reinterpret_cast<std::uintptr_t>(current_flink) - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                    LDR_DATA_TABLE_ENTRY entry{};
                    ReadProcessMemory(target_handle, reinterpret_cast<void*>(entry_address), &entry, sizeof(entry), nullptr);

                    std::wstring entry_name(entry.FullDllName.Length / sizeof(wchar_t), L'\0');
                    ReadProcessMemory(target_handle, entry.FullDllName.Buffer, entry_name.data(), entry.FullDllName.Length, nullptr);

                    auto cmp_entry_name = std::string(entry_name.end() - std::string(import_dll_name).size(), entry_name.end());

                    auto cmp_import_name = std::string(import_dll_name);

                    for (char& character : cmp_entry_name)
                    {
                        character = tolower(character);
                    }
                    for (char& character : cmp_import_name)
                    {
                        character = tolower(character);
                    }

                    if (cmp_entry_name == cmp_import_name)
                    {
                        found_dll = true;

                        iat_cursor->u1.Function = reinterpret_cast<std::uintptr_t>(entry.DllBase) + proc_offset;

                        break;
                    }

                    current_flink = entry.InMemoryOrderLinks.Flink;
                } while (current_flink != first_flink);
            }
            if (!found_dll)
            {

                import_section--;

                if (!load_missing_dll(std::string(import_dll_name)))
                    return false;
            }
        }

        return true;
    }

    inline bool load_dll(void*& allocated_base, dll& virt)
    {
        unsigned long old_protect{};
        if (!VirtualProtectEx(target_handle, allocated_base, virt.optional_header.SizeOfImage, PAGE_EXECUTE_READWRITE, &old_protect))
        {
            return false;
        }

        // Load Ready DLL
        if (!WriteProcessMemory(target_handle, allocated_base, virt.buffer.get(), virt.optional_header.SizeOfImage, nullptr))
        {
            return false;
        }

        return true;
    }

    inline bool map_dll(dll& phys, std::string_view& target_name)
    {
        // Get target process handle
        if (!get_process_handle(target_name))
            return false;

        // Allocate the memory
        void* allocated_base{};
        if (!allocate_dll_space(phys.optional_header.SizeOfImage, allocated_base))
            return false;

        // Create DLL for formatting
        dll virt{phys.nt_headers->OptionalHeader.SizeOfImage};
        create_virtual_dll(phys, virt);

        // Relocations
        handle_relocations(virt, allocated_base);

        // Fix imports
        if (!fix_imports(virt))
            return false;

        // Set Protections
        if (!load_dll(allocated_base, virt))
            return false;

        // Call DLL Main
        CreateRemoteThread(
                target_handle, 0, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<std::uintptr_t>(allocated_base) + virt.optional_header.AddressOfEntryPoint),
                0, 0, 0
        );

        // Clean up
        CloseHandle(target_handle);

        return true;
    }

    inline bool map_from_file_path(std::string_view& dll_name, std::string_view& target_name)
    {
        // Load file into byte array
        std::ifstream file(std::string(dll_name), std::ios::in | std::ios::binary);
        if (!file.is_open())
        {
            return false;
        }

        file.seekg(0, std::ios::end);
        std::streamsize filestream_buffer_size = file.tellg();
        auto filestream_buffer = std::make_unique<char[]>(filestream_buffer_size);

        file.seekg(std::ios::beg);
        file.read(reinterpret_cast<char*>(filestream_buffer.get()), filestream_buffer_size);

        dll phys{static_cast<std::uintptr_t>(filestream_buffer_size)};
        phys.buffer = std::move(filestream_buffer);
        phys.populate_headers();


        return map_dll(phys, target_name);
    }

    inline bool map_from_byte_array(std::unique_ptr<char[]>& buffer, std::size_t& size, std::string_view& target_name)
    {
        dll phys{size};
        phys.buffer = std::move(buffer);
        phys.populate_headers();

        return map_dll(phys, target_name);
    }
}
