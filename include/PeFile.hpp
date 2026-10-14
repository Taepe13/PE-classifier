#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace pe
{
    class RawFile
    {
        public:
            explicit RawFile(const std::filesystem::path& path);
            // Destructor
            ~RawFile() = default;
            // 
            RawFile(const RawFile&) = delete;
            RawFile& operator = (const RawFile&) = delete;
            //
            RawFile(RawFile&&) noexcept = default;
            RawFile& operator = (RawFile&&) noexcept = default;

            [[nodiscard]] const std::vector<uint8_t>& data() const noexcept {return data_;}
            [[nodiscard]] const std::filesystem::path& path() const noexcept {return path_;}
            [[nodiscard]] size_t size() const noexcept {return data_.size(); }

        private:
            std::filesystem::path path_;
            std::vector<uint8_t> data_;
    };
    [[nodiscard]] std::optional<RawFile> LoadFile(const std::filesystem::path& path);

    
}