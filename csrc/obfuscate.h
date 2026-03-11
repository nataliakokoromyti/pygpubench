// Copyright (c) 2026 Erik Schultheis
// SPDX-License-Identifier: Apache-2.0
//

#ifndef PYGPUBENCH_OBFUSCATE_H
#define PYGPUBENCH_OBFUSCATE_H

#include <string_view>
#include <random>

// A single memory page that can be read-protected.
// This does not provide any actual defence against an attacker,
// because they could always just remove memory protection before
// access. But that in itself serves to increase the complexity of
// an attack.
class ProtectablePage {
public:
    ProtectablePage();
    ~ProtectablePage();
    ProtectablePage(ProtectablePage&& other) noexcept;

    void lock();
    void unlock();

    void* Page = nullptr;
};

class ObfuscatedHexDigest : ProtectablePage {
public:
    ObfuscatedHexDigest() = default;

    void allocate(std::size_t size, std::mt19937& rng);
    [[nodiscard]] std::string_view view() const;

    void* data() {
        return Loc;
    }

    [[nodiscard]] std::size_t size() const {
        return Len;
    }
private:
    char* Loc = nullptr;
    std::size_t Len = 0;
};

void fill_random_hex(void* target, std::size_t size, std::mt19937& rng);

#endif //PYGPUBENCH_OBFUSCATE_H