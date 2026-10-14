#pragma once

#include "PeFile.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pe
{
    [[nodiscard]] const char* machineToString(uint16_t machine);
    [[nodiscard]] const char* optionalMagicToString(uint16_t magic);
    [[nodiscard]] const char* subsystemToString(uint16_t subsystem);
    [[nodiscard]] std::string fileCharacteristicsToString(uint16_t characteristics);
    [[nodiscard]] std::string dllCharacteristicsToString(uint16_t dllcharacteristics);
    [[nodiscard]] std::string sectionFlagsToString(uint32_t characteristics);
    struct SectionInfo
    {
        std::string name;
        uint32_t virtualAddress;
        uint32_t virtualSize;
        uint32_t rawOffset;
        uint32_t rawSize;
        uint32_t characteristics;
        double entropy;
    };

    struct ImportInfo
    {
        std::string dllName;
        std::vector<std::string> functions;
        std::vector<uint16_t> ordinals;
    };
    
    struct PeInfo
    {
        // DOS Header
        uint16_t dosMagic = 0;
        uint32_t e_lfanew = 0;

        // NT Header
        uint32_t ntSignature = 0;
        uint16_t machine = 0;
        uint16_t numberOfSections = 0;
        uint32_t timeDateStamp = 0;
        uint16_t characteristics = 0;

        // Optional Header
        uint16_t optionalMagic = 0;
        uint32_t addressOfEntryPoint = 0;
        uint64_t imageBase = 0;
        uint32_t sizeOfImage = 0;
        uint16_t subsystem = 0;
        uint16_t dllCharacteristics = 0;

        std::vector<SectionInfo> sections;
        std::vector<ImportInfo> imports;
    };

    class PeParser
    {
        public:
            explicit PeParser(const RawFile& file);

            [[nodiscard]] std::optional<PeInfo> parse();

            [[nodiscard]] uint32_t rvaToOffset(uint32_t rva) const;

        private:
            const RawFile& file_;
            PeInfo info_;

            bool parseDosHeaders();
            bool parseNtHeaders();
            bool parseSections();
            bool parseImports();

            template <typename T>
            [[nodiscard]] T readAt(size_t offset) const
            {
                if (offset + sizeof(T) > file_.size())
                {
                    throw std::out_of_range("Read out of range");
                }

                T value{};
                std::memcpy(&value, file_.data().data() + offset, sizeof(T));
                return value;
            }
            // Reading C-string to '\0' via offset
            [[nodiscard]] std::string readStringAt(size_t offset, size_t max_Len = 256) const;

        
    };


}