#include "PeFile.hpp"

#include <fstream>
#include <stdexcept>

namespace pe
{
    // Constructor RawFile.
    RawFile::RawFile(const std::filesystem::path& path) : path_(path)
    {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file)
        {
            throw std::runtime_error("Cannot open file: " + path.string());
        }

        // tellg() will return the size of current position.
        const std::streamsize size = file.tellg();
        if (size <= 0) 
        {
            throw std::runtime_error("File is empty: " + path.string());
        }

        file.seekg(0, std::ios::beg);

        data_.resize(static_cast<size_t>(size));

        if(!file.read(reinterpret_cast<char*>(data_.data()), size))
        {
            throw std::runtime_error("Cannot read file: " + path.string());
        }
    }
    std::optional<RawFile> LoadFile(const std::filesystem::path& path)
    {
        try 
        {
            return std::optional<RawFile>(std::in_place, path);
        }
        catch(const std::exception& e)
        {
            std::fprintf(stderr, "[!] Can not read a file + %s\n", e.what());
            return std::nullopt;
        }
    }
    
}