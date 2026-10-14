#include "Features.hpp"
#include "PeFile.hpp"
#include "PeParser.hpp"

#include <cstdio>
#include <filesystem>

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::fprintf(stderr, "Usage: %s <path_to_pe>\n", argv[0]);
        return 1;
    }

    const std::filesystem::path path = argv[1];

    auto fileOpt = pe::LoadFile(path);
    if (!fileOpt)
    {
        std::fprintf(stderr, "[!] Failed to load file: \n");
        return 1;
    }

    if (!fileOpt)
    {
        std::fprintf(stderr, "[!] Failed to load file\n");
        return 1;
    }

    std::printf("  ***************************************************\n\n");
    std::printf("  |Reading a file|\n Name: %s\n\n", path.string().c_str());
    std::printf("  Size: %zu bytes\n", fileOpt->size());
    std::printf("  ***************************************************\n\n");

    // Main parsing PE-structure

    pe::PeParser parser(*fileOpt);
    auto infoOpt = parser.parse();

    if(!infoOpt)
    {
        std::fprintf(stderr, "[!] Not a valid PE file\n");
        return 1;
    }

    const pe::PeInfo& info = *infoOpt;

    std::printf("  --------DOS HEADER----------------------------------------------------\n");
    std::printf("  DOS magic:              0x%X\n", info.dosMagic);
    std::printf("  e_lfanew:               0x%X\n", info.e_lfanew);

    std::printf("  --------NT HEADER-----------------------------------------------------\n");
    std::printf("  SIGNATURE:              0x%X  (PE)\n", info.ntSignature);
    std::printf("  Machine:                0x%X  (%s)\n", info.machine, pe::machineToString(info.machine));
    std::printf("  NumberOfSections:       0x%X\n", info.numberOfSections);
    std::printf("  TimeDateStamp:          0x%x\n", info.timeDateStamp);
    std::printf("  Characteristics:        0x%x     (%s)\n\n", info.characteristics, pe::fileCharacteristicsToString(info.characteristics).c_str());

    std::printf("  --------OPTIONAL HEADER-----------------------------------------------\n");
    std::printf("  Magic:                  0x%X   (%s)\n", info.optionalMagic, pe::optionalMagicToString(info.optionalMagic));
    std::printf("  AddressOfEntryPoint:    0x%x\n", info.addressOfEntryPoint);
    std::printf("  Imagebase:              0x%llX\n", static_cast<unsigned long long>(info.imageBase));
    std::printf("  SizeofImage             0x%X\n", info.sizeOfImage);
    std::printf("  Subsystem:              0x%X     (%s)\n", info.subsystem, pe::subsystemToString(info.subsystem));
    std::printf("  DllCharacteristics      0x%x  (%s)\n\n", info.dllCharacteristics, pe::dllCharacteristicsToString(info.dllCharacteristics).c_str());


    std::printf("  --------SECTIONS------------------------------------------------------\n");
    std::printf("  #  Name      VA          VS          Raw         Entropy  Flags\n");
    std::printf("  -  --------  ----------  ----------  ----------  -------  -----\n");
    for(size_t i = 0; i < info.sections.size(); i++)
    {
        const auto& sec = info.sections[i];
        std::printf("  %zu  %-8s  0x%08X  0x%08X  0x%08X  %7.4f  %s\n",
                                                                    i,
                                                                    sec.name.c_str(),
                                                                    sec.virtualAddress,
                                                                    sec.virtualSize,
                                                                    sec.rawOffset,
                                                                    sec.entropy,
                                                                    pe::sectionFlagsToString(sec.characteristics).c_str());

    }
    std::printf("\n");

    std::printf("  --------IMPORTS-----------------------------\n");
    if (info.imports.empty())
    {
        std::printf("   (none)\n\n");

    }
    else
    {
        for (const auto& imp : info.imports)
        {
            std::printf("  %s\n", imp.dllName.c_str());

            for (const auto& fn : imp.functions)
            {
                std::printf("      %s\n", fn.c_str());
            }

            for (uint16_t ord : imp.ordinals)
            {
                std::printf("      Ordinal: 0x%04X\n", ord);
            }
            std::printf("\n");
        }
    }

    // Features of classifier

    const pe::FeatureVector feature = pe::ExtractFeatures(*fileOpt, info);

    std::printf("  --------FEATURES (for ML classifier)--------\n");
    std::printf("  weightedEntropy:  %.6f\n", feature.weightedEntropy);
    std::printf("  stringsDensity:   %.6f\n", feature.stringsDensity);
    std::printf("  logSize           %.6f\n", feature.logSize);
    std::printf("\n");
}