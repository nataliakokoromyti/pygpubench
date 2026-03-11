// Copyright (c) 2026 Erik Schultheis
// SPDX-License-Identifier: Apache-2.0
//

#include "obfuscate.h"

#include <sys/mman.h>
#include <cstring>
#include <random>
#include <string_view>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <cerrno>
#include <cstdio>

constexpr std::size_t PAGE_SIZE = 4096;

ProtectablePage::ProtectablePage() {
    Page = mmap(nullptr, PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (Page == MAP_FAILED) {
        throw std::runtime_error("mmap failed");
    }
}

ProtectablePage::~ProtectablePage() {
    if (Page) {
        if (mprotect(Page, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
            std::perror("mprotect restore failed in ~ProtectablePage");
        }
        if (munmap(Page, PAGE_SIZE) != 0) {
            std::perror("munmap failed in ~ProtectablePage");
        }
    }
}

ProtectablePage::ProtectablePage(ProtectablePage&& other) noexcept : Page(std::exchange(other.Page, nullptr)){
}

void ProtectablePage::lock() {
    if (mprotect(Page, PAGE_SIZE, PROT_NONE) != 0) {
        throw std::system_error(errno, std::generic_category(), "mprotect(PROT_NONE) failed");
    }
}

void ProtectablePage::unlock() {
    if (mprotect(Page, PAGE_SIZE, PROT_READ) != 0) {
        throw std::system_error(errno, std::generic_category(), "mprotect(PROT_READ) failed");
    }
}

void ObfuscatedHexDigest::allocate(std::size_t size, std::mt19937& rng) {
    if (size > PAGE_SIZE / 2) {
        throw std::runtime_error("target size too big");
    }
    if (Len != 0 || Loc != nullptr) {
        throw std::runtime_error("already allocated");
    }

    fill_random_hex(Page, PAGE_SIZE, rng);
    const std::size_t max_offset = PAGE_SIZE - size - 1;
    std::uniform_int_distribution<std::size_t> offset_dist(0, max_offset);
    const std::size_t offset = offset_dist(rng);

    Len = size;
    Loc = static_cast<char*>(Page) + offset;
}

std::string_view ObfuscatedHexDigest::view() const {
    return {Loc, Len};
}

void fill_random_hex(void* target, std::size_t size, std::mt19937& rng) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::uniform_int_distribution<int> hex_dist(0, 15);
    auto* page_bytes = static_cast<char*>(target);
    for (std::size_t i = 0; i < size; i++) {
        page_bytes[i] = hex_chars[hex_dist(rng)];
    }
}
