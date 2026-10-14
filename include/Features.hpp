#pragma once

#include "PeParser.hpp"

#include <array>
#include <cstdint>
#include <string>

namespace pe
{
    struct FeatureVector
    {
        double weightedEntropy = 0.0;
        double stringsDensity = 0.0;
        double logSize = 0.0;

        [[nodiscard]] std::array<double, 3> toArray() const noexcept
        {
            return {weightedEntropy, stringsDensity, logSize};
        }

    };

    [[nodiscard]] FeatureVector ExtractFeatures(const RawFile& file, const PeInfo& info);
    [[nodiscard]] size_t CountStrings(const std::vector<uint8_t>& data, size_t minLen = 4);
}