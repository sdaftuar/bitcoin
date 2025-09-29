// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/frontier.h>

#include <cassert>
#include <cstdint>
#include <cstdlib>

namespace {

template<typename ValueType>
class NaiveFrontier
{
    std::vector<ValueType> m_data;

public:
    NaiveFrontier(size_t reserve, ValueType init) noexcept
    {
        m_data.assign(reserve + 1, init);
    }

    bool Set(size_t key, ValueType value) noexcept
    {
        bool ret = false;
        while (key < m_data.size() && value > m_data[key]) {
            m_data[key] = value;
            ret = true;
            ++key;
        }
        return ret;
    }

    bool Test(size_t key, ValueType value) const noexcept
    {
        return m_data.back() >= value;
    }

    std::pair<size_t, ValueType> Last() const noexcept
    {
        size_t key = m_data.size() - 1;
        while (key > 0 && m_data[key] == m_data[key - 1]) --key;
        return {key, m_data[key]};
    }

    bool PreviousTick(std::pair<size_t, ValueType>& cur) const noexcept
    {
        if (cur.first == 0) return false;
        --cur.first;
        cur.second = m_data[cur.first];
        while (cur.first > 0 && cur.second == m_data[cur.first - 1]) --cur.first;
        return true;
    }
};

} // namespace

FUZZ_TARGET(frontier)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());

    uint64_t min_value = provider.ConsumeIntegral<uint8_t>();
    size_t max_key = provider.ConsumeIntegral<uint8_t>();

    NaiveFrontier<uint64_t> naive_frontier(max_key, min_value);
    Frontier<uint64_t> frontier(max_key, min_value);

    LIMITED_WHILE(provider.remaining_bytes() > 0, 1000) {
        size_t key = provider.ConsumeIntegralInRange<size_t>(0, max_key);
        uint64_t value = provider.ConsumeIntegral<uint8_t>();
        bool ret1 = naive_frontier.Set(key, value);
        bool ret2 = frontier.Set(key, value);
        assert(ret1 == ret2);
    }

    auto cur1 = naive_frontier.Last();
    auto cur2 = frontier.Last();
    while (true) {
        assert(cur1 == cur2);
        bool cont1 = naive_frontier.PreviousTick(cur1);
        bool cont2 = frontier.PreviousTick(cur2);
        assert(cont1 == cont2);
        if (!cont1) break;
    }

    auto cur = naive_frontier.Last().first;
    while (true) {
        cur1.first = cur;
        cur2.first = cur;
        bool cont1 = naive_frontier.PreviousTick(cur1);
        bool cont2 = frontier.PreviousTick(cur2);
        assert(cur1 == cur2);
        assert(cont1 == cont2);
        if (cur == 0) break;
        --cur;
    }
}
