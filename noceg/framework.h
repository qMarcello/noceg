#pragma once

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers.

// Windows header files.
#include <windows.h>
#include <string>
#include <string_view>
#include <format>
#include <fstream>
#include <filesystem>
#include <cstdint>
#include <atomic>
#include <memory>
#include <optional>
#include <span>
#include <ranges>
#include <expected>
#include <log.h>

namespace fs = std::filesystem;

// JSON for Modern C++ (https://github.com/nlohmann/json)
#include <json/json.hpp>
using json = nlohmann::json;

// SafetyHook (https://github.com/cursey/safetyhook)
#include <safetyhook/safetyhook.hpp>