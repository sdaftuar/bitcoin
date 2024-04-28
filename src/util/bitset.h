// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BITSET_H
#define BITCOIN_UTIL_BITSET_H

#include <array>
#include <bit>
#include <cstdint>
#include <limits>
#include <type_traits>

#ifdef _MSC_VER
#  include <intrin.h>
#endif

/* This file provides data types similar to std::bitset, but adds the following functionality:
 *
 * - Efficient iteration over all set bits (compatible with range-based for loops).
 * - Efficient search for the first and last set bit (First() and Last()).
 * - Efficient set subtraction: (a / b) implements "a and not b".
 * - Efficient subset/superset testing: (a >> b) and (a << b).
 * - Efficient set overlap testing: a && b
 * - Efficient construction of set containing 0..N-1 (S::Fill).
 *
 * Other differences:
 * - BitSet<N> is a bitset that supports at least N elements, but may support more (Size() reports
 *   the actual number). Because the actual number is unpredictable, there are no operations that
 *   affect all positions (like std::bitset's operator~, flip(), or all()).
 * - Various other unimplemented features.
 */

namespace bitset_detail {

/** Count the number of bits set in an unsigned integer type. */
template<typename I>
unsigned inline PopCount(I v)
{
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    constexpr auto BITS = std::numeric_limits<I>::digits;
    // Algorithms from https://en.wikipedia.org/wiki/Hamming_weight#Efficient_implementation.
    // These seem to be faster than __builtin_popcount when compiling for non-SSE4 on x86_64.
    if constexpr (BITS <= 32) {
        v -= (v >> 1) & 0x55555555;
        v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
        v = (v + (v >> 4)) & 0x0f0f0f0f;
        v += v >> 8;
        v += v >> 16;
        return v & 0x3f;
    } else {
        static_assert(BITS <= 64);
        v -= (v >> 1) & 0x5555555555555555;
        v = (v & 0x3333333333333333) + ((v >> 2) & 0x3333333333333333);
        v = (v + (v >> 4)) & 0x0f0f0f0f0f0f0f0f;
        return (v * uint64_t{0x0101010101010101}) >> 56;
    }
}

/** A bitset implementation backed by a single integer of type I. */
template<typename I>
class IntBitSet
{
    // Only binary, unsigned, integer, types allowed.
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    /** The maximum number of bits this bitset supports. */
    static constexpr unsigned MAX_SIZE = std::numeric_limits<I>::digits;
    /** Integer whose bits represent this bitset. */
    I m_val;
    /** Internal constructor with a given integer as contents. */
    IntBitSet(I val) noexcept : m_val{val} {}
    /** Dummy type to return using end(). Only used for comparing with Iterator. */
    class IteratorEnd
    {
        friend class IntBitSet;
        IteratorEnd() = default;
    public:
        IteratorEnd(const IteratorEnd&) = default;
    };
    /** Iterator type returned by begin(), which efficiently iterates all 1 positions. */
    class Iterator
    {
        friend class IntBitSet;
        I m_val; /**< The original integer's remaining bits. */
        unsigned m_pos; /** Last reported 1 position (if m_pos != 0). */
        Iterator(I val) noexcept : m_val(val), m_pos(0)
        {
            if (m_val != 0) m_pos = std::countr_zero(m_val);
        }
    public:
        /** Do not allow external code to construct an Iterator. */
        Iterator() = delete;
        // Copying is allowed.
        Iterator(const Iterator&) noexcept = default;
        Iterator& operator=(const Iterator&) noexcept = default;
        /** Test whether we are not yet done (can only compare with IteratorEnd). */
        friend bool operator!=(const Iterator& a, const IteratorEnd&) noexcept
        {
            return a.m_val != 0;
        }
        /** Test whether we are done (can only compare with IteratorEnd). */
        friend bool operator==(const Iterator& a, const IteratorEnd&) noexcept
        {
            return a.m_val == 0;
        }
        /** Progress to the next 1 bit (only if != IteratorEnd). */
        Iterator& operator++() noexcept
        {
            m_val &= m_val - I{1U};
            if (m_val != 0) m_pos = std::countr_zero(m_val);
            return *this;
        }
        /** Get the current bit position (only if != IteratorEnd). */
        const unsigned& operator*() const noexcept { return m_pos; }
    };

public:
    /** Construct an all-zero bitset. */
    IntBitSet() noexcept : m_val{0} {}
    /** Copy construct a bitset. */
    IntBitSet(const IntBitSet&) noexcept = default;
    /** Copy assign a bitset. */
    IntBitSet& operator=(const IntBitSet&) noexcept = default;
    /** Construct a bitset with bits 0..count-1 (inclusive) set to 1. */
    static IntBitSet Fill(unsigned count) noexcept {
        IntBitSet ret;
        if (count) ret.m_val = I(~I{0}) >> (MAX_SIZE - count);
        return ret;
    }
    /** Compute the number of 1 bits in the bitset. */
    unsigned Count() const noexcept { return PopCount(m_val); }
    /** Return the number of bits that this object holds. */
    static constexpr unsigned Size() noexcept { return MAX_SIZE; }
    /** Set a bit to 1. */
    void Set(unsigned pos) noexcept { m_val |= I{1U} << pos; }
    /** Set a bit to the specified value. */
    void Set(unsigned pos, bool val) noexcept { m_val = (m_val & ~I(I{1U} << pos)) | (I(val) << pos); }
    /** Set a bit to 0. */
    void Reset(unsigned pos) noexcept { m_val &= ~I(I{1U} << pos); }
    /** Retrieve a bit at the given position. */
    bool operator[](unsigned pos) const noexcept { return (m_val >> pos) & 1U; }
    /** Check if all bits are 0. */
    bool None() const noexcept { return m_val == 0; }
    /** Check if any bits are 1. */
    bool Any() const noexcept { return m_val != 0; }
    /** Return an object that iterates over all 1 bits (++ and * only allowed when != end()). */
    Iterator begin() const noexcept { return Iterator(m_val); }
    /** Return a dummy object to compare Iterators with. */
    IteratorEnd end() const noexcept { return IteratorEnd(); }
    /** Find the first element (requires Any()). */
    unsigned First() const noexcept { return std::countr_zero(m_val); }
    /** Find the last element (requires Any()). */
    unsigned Last() const noexcept { return std::bit_width(m_val) - 1; }
    /** Set this object's bits to be the binary AND between respective bits from this and a. */
    IntBitSet& operator|=(const IntBitSet& a) noexcept { m_val |= a.m_val; return *this; }
    /** Set this object's bits to be the binary OR between respective bits from this and a. */
    IntBitSet& operator&=(const IntBitSet& a) noexcept { m_val &= a.m_val; return *this; }
    /** Set this object's bits to be the binary AND NOT between respective bits from this and a. */
    IntBitSet& operator/=(const IntBitSet& a) noexcept { m_val &= ~a.m_val; return *this; }
    /** Check if the intersection between two sets is non-empty. */
    friend bool operator&&(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val & b.m_val; }
    /** Return an object with the binary AND between respective bits from a and b. */
    friend IntBitSet operator&(const IntBitSet& a, const IntBitSet& b) noexcept { return {I(a.m_val & b.m_val)}; }
    /** Return an object with the binary OR between respective bits from a and b. */
    friend IntBitSet operator|(const IntBitSet& a, const IntBitSet& b) noexcept { return {I(a.m_val | b.m_val)}; }
    /** Return an object with the binary AND NOT between respective bits from a and b. */
    friend IntBitSet operator/(const IntBitSet& a, const IntBitSet& b) noexcept { return {I(a.m_val & ~b.m_val)}; }
    /** Check if bitset a and bitset b are identical. */
    friend bool operator==(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val == b.m_val; }
    /** Check if bitset a and bitset b are different. */
    friend bool operator!=(const IntBitSet& a, const IntBitSet& b) noexcept { return a.m_val != b.m_val; }
    /** Check if bitset a is a superset of bitset b (= every 1 bit in b is also in a). */
    friend bool operator>>(const IntBitSet& a, const IntBitSet& b) noexcept { return (b.m_val & ~a.m_val) == 0; }
    /** Check if bitset a is a subset of bitset b (= every 1 bit in a is also in b). */
    friend bool operator<<(const IntBitSet& a, const IntBitSet& b) noexcept { return (a.m_val & ~b.m_val) == 0; }
    /** Swap two bitsets. */
    friend void swap(IntBitSet& a, IntBitSet& b) noexcept { std::swap(a.m_val, b.m_val); }
};

/** A bitset implementation backed by N integers of type I. */
template<typename I, unsigned N>
class MultiIntBitSet
{
    // Only binary, unsigned, integer, types allowed.
    static_assert(std::is_integral_v<I> && std::is_unsigned_v<I> && std::numeric_limits<I>::radix == 2);
    /** The number of bits per integer. */
    static constexpr unsigned LIMB_BITS = std::numeric_limits<I>::digits;
    /** Number of elements this set type supports. */
    static constexpr unsigned MAX_SIZE = LIMB_BITS * N;
    /** Array whose member integers store the bits of the set. */
    std::array<I, N> m_val{};
    /** Dummy type to return using end(). Only used for comparing with Iterator. */
    class IteratorEnd
    {
        friend class MultiIntBitSet;
        IteratorEnd() = default;
    public:
        IteratorEnd(const IteratorEnd&) = default;
    };
    /** Iterator type returned by begin(), which efficiently iterates all 1 positions. */
    class Iterator
    {
        friend class MultiIntBitSet;
        const std::array<I, N>* m_ptr; /**< Pointer to array to fetch bits from. */
        I m_val; /**< The remaining bits of (*m_ptr)[m_idx]. */
        unsigned m_pos; /**< The last reported position. */
        unsigned m_idx; /**< The index in *m_ptr currently being iterated over. */
        Iterator(const std::array<I, N>* ptr) noexcept : m_ptr(ptr), m_idx(0)
        {
            do {
                m_val = (*m_ptr)[m_idx];
                if (m_val) {
                    m_pos = std::countr_zero(m_val) + m_idx * LIMB_BITS;
                    break;
                }
                ++m_idx;
            } while(m_idx < N);
        }

    public:
        /** Do not allow external code to construct an Iterator. */
        Iterator() = delete;
        // Copying is allowed.
        Iterator(const Iterator&) noexcept = default;
        Iterator& operator=(const Iterator&) noexcept = default;
        /** Test whether we are not yet done (can only compare with IteratorEnd). */
        friend bool operator!=(const Iterator& a, const IteratorEnd&) noexcept
        {
            return a.m_idx != N;
        }
        /** Test whether we are done (can only compare with IteratorEnd). */
        friend bool operator==(const Iterator& a, const IteratorEnd&) noexcept
        {
            return a.m_idx == N;
        }
        /** Progress to the next 1 bit (only if != IteratorEnd). */
        Iterator& operator++() noexcept
        {
            m_val &= m_val - I{1U};
            if (m_val == 0) {
                while (true) {
                    ++m_idx;
                    if (m_idx == N) break;
                    m_val = (*m_ptr)[m_idx];
                    if (m_val) {
                        m_pos = std::countr_zero(m_val) + m_idx * LIMB_BITS;
                        break;
                    }
                }
            } else {
                m_pos = std::countr_zero(m_val) + m_idx * LIMB_BITS;
            }
            return *this;
        }
        /** Get the current bit position (only if != IteratorEnd). */
        const unsigned& operator*() const noexcept { return m_pos; }
    };

public:
    /** Construct an all-zero bitset. */
    MultiIntBitSet() noexcept {}
    /** Copy construct a bitset. */
    MultiIntBitSet(const MultiIntBitSet&) noexcept = default;
    /** Copy assign a bitset. */
    MultiIntBitSet& operator=(const MultiIntBitSet&) noexcept = default;
    /** Set a bit to 1. */
    void Set(unsigned pos) noexcept { m_val[pos / LIMB_BITS] |= I{1U} << (pos % LIMB_BITS); }
    /** Set a bit to the specified value. */
    void Set(unsigned pos, bool val) noexcept { m_val[pos / LIMB_BITS] = (m_val[pos / LIMB_BITS] & ~I(I{1U} << (pos % LIMB_BITS))) | (I{val} << (pos % LIMB_BITS)); }
    /** Set a bit to 0. */
    void Reset(unsigned pos) noexcept { m_val[pos / LIMB_BITS] &= ~I(I{1U} << (pos % LIMB_BITS)); }
    /** Retrieve a bit at the given position. */
    bool operator[](unsigned pos) const noexcept { return (m_val[pos / LIMB_BITS] >> (pos % LIMB_BITS)) & 1U; }
    /** Construct a bitset with bits 0..count-1 (inclusive) set to 1. */
    static MultiIntBitSet Fill(unsigned count) noexcept {
        MultiIntBitSet ret;
        if (count) {
            unsigned i = 0;
            while (count > LIMB_BITS) {
                ret.m_val[i++] = ~I{0};
                count -= LIMB_BITS;
            }
            ret.m_val[i] = I(~I{0}) >> (LIMB_BITS - count);
        }
        return ret;
    }
    /** Return the number of bits that this object holds. */
    static constexpr unsigned Size() noexcept { return MAX_SIZE; }
    /** Compute the number of 1 bits in the bitset. */
    unsigned Count() const noexcept
    {
        unsigned ret{0};
        for (I v : m_val) ret += PopCount(v);
        return ret;
    }
    /** Check if all bits are 0. */
    bool None() const noexcept
    {
        for (auto v : m_val) {
            if (v != 0) return false;
        }
        return true;
    }
    /** Check if any bits are 1. */
    bool Any() const noexcept
    {
        for (auto v : m_val) {
            if (v != 0) return true;
        }
        return false;
    }
    /** Return an object that iterates over all 1 bits (++ and * only allowed when != end()). */
    Iterator begin() const noexcept { return Iterator(&m_val); }
    /** Return a dummy object to compare Iterators with. */
    IteratorEnd end() const noexcept { return IteratorEnd(); }
    /** Find the first element (requires Any()). */
    unsigned First() const noexcept
    {
        unsigned p = 0;
        while (m_val[p] == 0) ++p;
        return std::countr_zero(m_val[p]) + p * LIMB_BITS;
    }
    /** Find the last element (requires Any()). */
    unsigned Last() const noexcept
    {
        unsigned p = N - 1;
        while (m_val[p] == 0) --p;
        return std::bit_width(m_val[p]) - 1 + p * LIMB_BITS;
    }
    /** Set this object's bits to be the binary OR between respective bits from this and a. */
    MultiIntBitSet& operator|=(const MultiIntBitSet& a) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            m_val[i] |= a.m_val[i];
        }
        return *this;
    }
    /** Set this object's bits to be the binary AND between respective bits from this and a. */
    MultiIntBitSet& operator&=(const MultiIntBitSet& a) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            m_val[i] &= a.m_val[i];
        }
        return *this;
    }
    /** Set this object's bits to be the binary AND NOT between respective bits from this and a. */
    MultiIntBitSet& operator/=(const MultiIntBitSet& a) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            m_val[i] &= ~a.m_val[i];
        }
        return *this;
    }
    /** Check whether the intersection between two sets is non-empty. */
    friend bool operator&&(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            if (a.m_val[i] & b.m_val[i]) return true;
        }
        return false;
    }
    /** Return an object with the binary AND between respective bits from a and b. */
    friend MultiIntBitSet operator&(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] & b.m_val[i];
        }
        return r;
    }
    /** Return an object with the binary OR between respective bits from a and b. */
    friend MultiIntBitSet operator|(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] | b.m_val[i];
        }
        return r;
    }
    /** Return an object with the binary AND NOT between respective bits from a and b. */
    friend MultiIntBitSet operator/(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        MultiIntBitSet r;
        for (unsigned i = 0; i < N; ++i) {
            r.m_val[i] = a.m_val[i] & ~b.m_val[i];
        }
        return r;
    }
    /** Check if bitset a is a superset of bitset b (= every 1 bit in b is also in a). */
    friend bool operator>>(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            if (b.m_val[i] & ~a.m_val[i]) return false;
        }
        return true;
    }
    /** Check if bitset a is a subset of bitset b (= every 1 bit in a is also in b). */
    friend bool operator<<(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept
    {
        for (unsigned i = 0; i < N; ++i) {
            if (a.m_val[i] & ~b.m_val[i]) return false;
        }
        return true;
    }
    /** Check if bitset a and bitset b are identical. */
    friend bool operator==(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept { return a.m_val == b.m_val; }
    /** Check if bitset a and bitset b are different. */
    friend bool operator!=(const MultiIntBitSet& a, const MultiIntBitSet& b) noexcept { return a.m_val != b.m_val; }
    /** Swap two bitsets. */
    friend void swap(MultiIntBitSet& a, MultiIntBitSet& b) noexcept { std::swap(a.m_val, b.m_val); }
};

} // namespace bitset_detail

template<unsigned BITS>
using BitSet = std::conditional_t<(BITS <= 32), bitset_detail::IntBitSet<uint32_t>,
               std::conditional_t<(BITS <= std::numeric_limits<size_t>::digits), bitset_detail::IntBitSet<size_t>,
               bitset_detail::MultiIntBitSet<size_t, (BITS + std::numeric_limits<size_t>::digits - 1) / std::numeric_limits<size_t>::digits>>>;

#endif // BITCOIN_UTIL_BITSET_H
