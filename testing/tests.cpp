#include <print>
#include "mapper.h"


int main(int argc, char* argv[])
{
    std::println("Testing Load By file.");
    std::string_view dll_name = argv[1];
    std::string_view target_name = argv[2];

    return !mapper::map_from_file_path(dll_name, target_name);
}


/*int main(int argc, char* argv[])
{
    std::println("Testing Load By Byte Array.");
    std::string_view dll_name = argv[1];
    std::string_view target_name = argv[2];

    std::ifstream file(std::string(dll_name), std::ios::in | std::ios::binary);
    if (!file.is_open())
    {
        return 1;
    }

    file.seekg(0, std::ios::end);
    std::streamsize filestream_buffer_size = file.tellg();
    auto filestream_buffer = std::make_unique<char[]>(filestream_buffer_size);

    file.seekg(std::ios::beg);
    file.read(reinterpret_cast<char*>(filestream_buffer.get()), filestream_buffer_size);

    auto size = static_cast<std::size_t>(filestream_buffer_size);

    return !mapper::map_from_byte_array(filestream_buffer, size, target_name);
}*/
