#include "PeParser.hpp"

#include <cmath>
#include <cstring>
#include <array>
#include <Windows.h>

#define WIN32_LEAN_AND_MEAN 
#define NOMINMAX

namespace pe
{
    const char* machineToString(uint16_t machine)
    {
        switch(machine)
        {
            case IMAGE_FILE_MACHINE_I386: return "x86 (i386)";
            case IMAGE_FILE_MACHINE_AMD64: return "x64 (AMD64)";
            case IMAGE_FILE_MACHINE_ARM: return "ARM";
            case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
            case IMAGE_FILE_MACHINE_IA64: return "IA64 (Itanium)";
            default: return "Unknown";
        }
    }
    const char* optionalMagicToString(uint16_t magic)
    {
        switch(magic)
        {
            case IMAGE_NT_OPTIONAL_HDR32_MAGIC: return "PE32 (x86)";
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC: return "PE32+ (x64)";
            case IMAGE_ROM_OPTIONAL_HDR_MAGIC: return "ROM";
            default: return "Unknown";
        }
    }
    const char* subsystemToString(uint16_t subsystem)
    {
        switch(subsystem)
        {
            case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "WINDOWS GUI";
            case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "CONSOLE APP";
            case IMAGE_SUBSYSTEM_POSIX_CUI: return "POSIX CONSOLE";
            case IMAGE_SUBSYSTEM_NATIVE: return "Native";
            case IMAGE_SUBSYSTEM_XBOX: return "XBOX";
            case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "Windows BOOT";
            case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI Application";
            case IMAGE_SUBSYSTEM_UNKNOWN: return "Unknown subsystem";
            default: return "Unknown subsystem";
        }
    }

    std::string fileCharacteristicsToString(uint16_t c)
    {
        std::string result;
        // auto lambda to add a flag if already installed
        auto add = [&result](bool cond, const char* name)
        {
            if (cond) 
            {
                result += name;
                result += ' ';
            }
        };

    add(c & IMAGE_FILE_RELOCS_STRIPPED,         "RELOCS_STRIPPED");
    add(c & IMAGE_FILE_EXECUTABLE_IMAGE,        "EXECUTABLE_IMAGE");
    add(c & IMAGE_FILE_LINE_NUMS_STRIPPED,      "LINE_NUMS_STRIPPED");
    add(c & IMAGE_FILE_LOCAL_SYMS_STRIPPED,     "LOCAL_SYMS_STRIPPED");
    add(c & IMAGE_FILE_LARGE_ADDRESS_AWARE,     "LARGE_ADDRESS_AWARE");
    add(c & IMAGE_FILE_32BIT_MACHINE,           "32BIT_MACHINE");
    add(c & IMAGE_FILE_DEBUG_STRIPPED,          "DEBUG_STRIPPED");
    add(c & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP");
    add(c & IMAGE_FILE_NET_RUN_FROM_SWAP,       "NET_RUN_FROM_SWAP");
    add(c & IMAGE_FILE_SYSTEM,                  "SYSTEM");
    add(c & IMAGE_FILE_DLL,                     "DLL");
    add(c & IMAGE_FILE_UP_SYSTEM_ONLY,          "UP_SYSTEM_ONLY");
    if (!result.empty()) result.pop_back();  
    return result;
    }

    std::string dllCharacteristicsToString(uint16_t c) 
    {
    std::string result;

    // auto lambda to add a flag if already installed
    auto add = [&result](bool cond, const char* name) {
        if (cond) { result += name; result += ' '; }
    };
    add(c & 0x0020, "HIGH_ENTROPY_VA");
    add(c & 0x0040, "DYNAMIC_BASE");
    add(c & 0x0080, "FORCE_INTEGRITY");
    add(c & 0x0100, "NX_COMPAT");
    add(c & 0x0200, "NO_ISOLATION");
    add(c & 0x0400, "NO_SEH");
    add(c & 0x0800, "NO_BIND");
    add(c & 0x1000, "APPCONTAINER");
    add(c & 0x2000, "WDM_DRIVER");
    add(c & 0x4000, "GUARD_CF");
    add(c & 0x8000, "TERMINAL_SERVER_AWARE");
    if (!result.empty()) result.pop_back();
    return result;
    }

    std::string sectionFlagsToString(uint32_t c)
    {
        std::string result;
        result += (c & IMAGE_SCN_MEM_READ) ? 'R' : '-';
        result += (c & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
        result += (c & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';

        return result;
    }


    // Main PeParser
    PeParser::PeParser(const RawFile& file) : file_(file) {}

    // readStringAt: reading bytes until '\0'
    std::string PeParser::readStringAt(size_t offset, size_t maxLen) const
    {
        std::string result;
        result.reserve(maxLen); // less allocations
        const auto& data = file_.data();
        for (size_t i = 0; i < maxLen; i++)
        {
            if (offset + i >= data.size()) break;
            char ch = static_cast<char>(data[offset + i]);
            if (ch == '\0') break;
            result += ch;
        }
        return result;
    }
    // Offset = RVA - VirtualAddress + PointerToRawData
    uint32_t PeParser::rvaToOffset(uint32_t rva) const 
    {
        for (const auto& sec: info_.sections)
        {
            if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize)
            {
                return sec.rawOffset + (rva - sec.virtualAddress);
            }
        }
        return rva;
    }

    bool PeParser::parseDosHeaders()
    {
        if(file_.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        const auto dos = readAt<IMAGE_DOS_HEADER>(0);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
        info_.dosMagic = dos.e_magic;
        info_.e_lfanew = dos.e_lfanew;
        return true;
    }

    bool PeParser::parseNtHeaders()
    {
        const size_t ntOffset = info_.e_lfanew;
        if(ntOffset + sizeof(IMAGE_NT_HEADERS) > file_.size()) return false;

        const auto nt = readAt<IMAGE_NT_HEADERS>(ntOffset);
        if (nt.Signature != IMAGE_NT_SIGNATURE) return false;

        info_.ntSignature = nt.Signature;
        info_.machine = nt.FileHeader.Machine;
        info_.numberOfSections = nt.FileHeader.NumberOfSections;
        info_.characteristics = nt.FileHeader.Characteristics;
        
        info_.optionalMagic = nt.OptionalHeader.Magic;
        info_.addressOfEntryPoint = nt.OptionalHeader.AddressOfEntryPoint;
        info_.imageBase = nt.OptionalHeader.ImageBase;
        info_.sizeOfImage = nt.OptionalHeader.SizeOfImage;
        info_.subsystem = nt.OptionalHeader.Subsystem;
        info_.dllCharacteristics = nt.OptionalHeader.DllCharacteristics;

        return true;
    }

    static double findEntropy(const uint8_t* data, size_t size)
    {
        double entropy = 0.0;
        if(size == 0) return 0.0;
        std::array<size_t, 256> histogram{};
        for (size_t i = 0; i < size; i++)
        {
            histogram[data[i]]++;
        }
        for (size_t count : histogram)
        {
            if (count == 0) continue;
            const double p = static_cast<double>(count) / static_cast<double>(size);
            entropy = entropy - p * std::log2(p); // H = -sum(p_i * log2(p_i)) where p_i - periodicity of byte i
        }
        return entropy;
        
    }
    
    bool PeParser::parseSections()
    {
        const size_t ntOffset = info_.e_lfanew;
        const size_t firstSectionOffset = ntOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + readAt<IMAGE_FILE_HEADER>(ntOffset + offsetof(IMAGE_NT_HEADERS, FileHeader)).SizeOfOptionalHeader; // firstSectionOffset = e_lfanew + size of NT_HEADER.

        for (uint16_t i = 0; i < info_.numberOfSections; i++)
        {
            const size_t secOffset = firstSectionOffset + i * sizeof(IMAGE_SECTION_HEADER);
            if (secOffset + sizeof(IMAGE_SECTION_HEADER) > file_.size()) break;
            
            const auto sh = readAt<IMAGE_SECTION_HEADER>(secOffset);

            SectionInfo sec;

            sec.name = std::string(reinterpret_cast<const char*>(sh.Name), 8);

            sec.name = sec.name.c_str();
            sec.virtualAddress = sh.VirtualAddress;
            sec.virtualSize = sh.Misc.VirtualSize;
            sec.rawOffset = sh.PointerToRawData;
            sec.rawSize = sh.SizeOfRawData;
            sec.characteristics = sh.Characteristics;

            if (sec.rawOffset + sec.rawSize <= file_.size() && sec.rawSize > 0)
            {
                sec.entropy = findEntropy(file_.data().data() + sec.rawOffset, sec.rawSize);
            }

            info_.sections.push_back(std::move(sec));
        }
        return true;
    }

    bool PeParser::parseImports()
    {
        const size_t ntOffset = info_.e_lfanew;
        const auto optHeader = readAt<IMAGE_OPTIONAL_HEADER>(ntOffset + offsetof(IMAGE_NT_HEADERS, OptionalHeader));
        const uint32_t importRva = optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRva == 0) return true;

        size_t importOffset = rvaToOffset(importRva);

        while (true)
        {
            if (importOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > file_.size()) break;
            const auto desc = readAt<IMAGE_IMPORT_DESCRIPTOR>(importOffset);
            if (desc.Name == 0) break;

            ImportInfo imp;
            imp.dllName = readStringAt(rvaToOffset(desc.Name));

            size_t thunkOffset = rvaToOffset(desc.OriginalFirstThunk);
            
            if (desc.OriginalFirstThunk == 0)
            {
                thunkOffset = rvaToOffset(desc.FirstThunk);
            }

            while (true)
            {
                if (thunkOffset + sizeof(uint64_t) > file_.size()) break;
                const uint64_t thunk = readAt<uint64_t>(thunkOffset);
                if (thunk == 0) break;

                constexpr uint64_t ORDINAL_FLAG = 0x8000000000000000ULL;
                if (thunk & ORDINAL_FLAG)
                {
                    imp.ordinals.push_back(static_cast<uint16_t>(thunk & 0xFFFF));

                }
                else
                {
                    const size_t nameOffset = rvaToOffset(static_cast<uint32_t>(thunk));
                    // First 2 bytes - Hint
                    imp.functions.push_back(readStringAt(nameOffset + 2));
                }

                thunkOffset += sizeof(uint64_t);
            }

            info_.imports.push_back(std::move(imp));
            importOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
        return true;

        
    }

    std::optional<PeInfo> PeParser::parse()
    {
        try
        {
            if(!parseDosHeaders()) return std::nullopt;
            if(!parseNtHeaders()) return std::nullopt;
            if(!parseSections()) return std::nullopt;
            if(!parseImports()) return std::nullopt;
            return info_;
        }
        catch (const std::exception& e)
        {
            std::fprintf(stderr, "[!] Can not parse: \n%s\n", e.what());
            return std::nullopt;
        }

    }
}
