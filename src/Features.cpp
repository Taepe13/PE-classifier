#include "Features.hpp"

#include <cmath>
#include <cctype>

namespace pe
{
    size_t CountStrings(const std::vector<uint8_t>& data, size_t minLen)
    {
        size_t count = 0;
        size_t currentLen = 0;

        for (uint8_t b : data)
        {
            //printable symbols can be from 0x20 to 0x7E and it can't be \r \n \t
            const bool isPrintable = (b >= 0x20 && b <= 0x7E) && b != '\r' && b != '\n' && b != '\t';

            if (isPrintable)
            {
                ++currentLen;
            }
            else
            {
                if (currentLen >= minLen) ++count;
                currentLen = 0;
            }


        }
        if (currentLen >= minLen) ++ count;

        return count;
    }

    FeatureVector ExtractFeatures(const RawFile& file, const PeInfo& info)
    {
        FeatureVector fv;

        double weightedSum = 0.0;
        double totalWeight = 0.0;
        for (const auto& sec : info.sections)
        {
            if (sec.rawSize > 0)
            {
                weightedSum += sec.entropy * static_cast<double>(sec.rawSize);
                totalWeight += static_cast<double>(sec.rawSize);
            }
        }
        fv.weightedEntropy = (totalWeight > 0.0) ? (weightedSum / totalWeight) : 0.0;

        const size_t numStrings = CountStrings(file.data(), 4);
        const double sizeKb = static_cast<double>(file.size() / 1024.0);

        fv.stringsDensity = static_cast<double>(numStrings) / std::max(sizeKb, 1e-6);

        fv.logSize = std::log10(static_cast<double>(file.size()) + 1.0);

        return fv;
    }
}