// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLUSTER_LINEARIZE_H
#define BITCOIN_CLUSTER_LINEARIZE_H

#include <span.h>

#include <stdint.h>
#include <algorithm>
#include <limits>
#include <numeric>
#include <optional>
#include <vector>
#include <tuple>
#include <deque>

#include <util/bitset.h>
#include <util/feefrac.h>
#include <test/util/xoroshiro128plusplus.h>

#include <assert.h>

#if !defined(DEBUG_LINEARIZE)
#  if defined(PROVIDE_FUZZ_MAIN_FUNCTION)
#    define DEBUG_LINEARIZE 0
#  else
#    define DEBUG_LINEARIZE 1
#  endif
#endif

namespace cluster_linearize {

namespace {

/** Data type to represent cluster input.
 *
 * cluster[i].first is tx_i's fee and size.
 * cluster[i].second[j] is true iff tx_i spends one or more of tx_j's outputs.
 */
template<typename S>
using Cluster = std::vector<std::pair<FeeFrac, S>>;

/** Precomputation data structure with all ancestor sets of a cluster. */
template<typename S>
class AncestorSets
{
    std::vector<S> m_ancestorsets;

public:
    explicit AncestorSets(const Cluster<S>& cluster)
    {
        // Initialize: every transaction's ancestor set is itself plus direct parents.
        m_ancestorsets.resize(cluster.size());
        for (size_t i = 0; i < cluster.size(); ++i) {
            m_ancestorsets[i] = cluster[i].second;
            m_ancestorsets[i].Set(i);
        }

        // Propagate
        for (unsigned i = 0; i < cluster.size(); ++i) {
            // At this point, m_ancestorsets[a][b] is true iff b is an ancestor of a and there is
            // a path from a to b through the subgraph consisting of {a, b, 0, 1, ..(i-1)}.
            S to_merge = m_ancestorsets[i];
            for (unsigned j = 0; j < cluster.size(); ++j) {
                if (m_ancestorsets[j][i]) {
                    m_ancestorsets[j] |= to_merge;
                }
            }
        }
    }

    AncestorSets() noexcept = default;
    AncestorSets(const AncestorSets&) = delete;
    AncestorSets(AncestorSets&&) noexcept = default;
    AncestorSets& operator=(const AncestorSets&) = delete;
    AncestorSets& operator=(AncestorSets&&) noexcept = default;

    const S& operator[](unsigned pos) const noexcept { return m_ancestorsets[pos]; }
    size_t Size() const noexcept { return m_ancestorsets.size(); }
};

/** Precomputation data structure with all descendant sets of a cluster. */
template<typename S>
class DescendantSets
{
    std::vector<S> m_descendantsets;

public:
    explicit DescendantSets(const AncestorSets<S>& anc)
    {
        m_descendantsets.resize(anc.Size());
        for (size_t i = 0; i < anc.Size(); ++i) {
            for (unsigned j : anc[i]) {
                m_descendantsets[j].Set(i);
            }
        }
    }

    DescendantSets() noexcept = default;
    DescendantSets(const DescendantSets&) = delete;
    DescendantSets(DescendantSets&&) noexcept = default;
    DescendantSets& operator=(const DescendantSets&) = delete;
    DescendantSets& operator=(DescendantSets&&) noexcept = default;

    const S& operator[](unsigned pos) const noexcept { return m_descendantsets[pos]; }
    size_t Size() const noexcept { return m_descendantsets.size(); }
};

/** Output of FindBestCandidateSet* functions. */
template<typename S>
struct CandidateSetAnalysis
{
    /** Total number of candidate sets found/considered. */
    size_t num_candidate_sets{0};
    /** Best found candidate set. */
    S best_candidate_set{};
    /** Fee and size of best found candidate set. */
    FeeFrac best_candidate_feefrac{};
    /** Index of the chosen transaction (ancestor set algorithm only). */
    unsigned chosen_transaction{0};

    /** Maximum search queue size. */
    size_t max_queue_size{0};
    /** Total number of queue processing iterations performed. */
    size_t iterations{0};
    /** Number of feefrac comparisons performed. */
    size_t comparisons{0};
};

/** Compute the combined fee and size of a subset of a cluster. */
template<typename S>
FeeFrac ComputeSetFeeFrac(const Cluster<S>& cluster, const S& select)
{
    FeeFrac ret;
    for (unsigned i : select) ret += cluster[i].first;
    return ret;
}

/** Precomputed ancestor FeeFracs. */
template<typename S>
class AncestorSetFeeFracs
{
    std::vector<FeeFrac> m_anc_feefracs;
    S m_done;

public:
    /** Construct a precomputed AncestorSetFeeFracs object for given cluster/done. */
    explicit AncestorSetFeeFracs(const Cluster<S>& cluster, const AncestorSets<S>& anc, const S& done) noexcept
    {
        m_anc_feefracs.resize(cluster.size());
        m_done = done;
        for (unsigned i = 0; i < cluster.size(); ++i) {
            if (!done[i]) {
                m_anc_feefracs[i] = ComputeSetFeeFrac(cluster, anc[i] / done);
            }
        }
    }

    /** Update the precomputed data structure to reflect that set new_done was added to done. */
    void Done(const Cluster<S>& cluster, const DescendantSets<S>& desc, const S& new_done) noexcept
    {
#if DEBUG_LINEARIZE
        assert(!(m_done && new_done));
#endif
        m_done |= new_done;
        for (unsigned pos : new_done) {
            FeeFrac feefrac = cluster[pos].first;
            for (unsigned i : desc[pos] / m_done) {
                m_anc_feefracs[i] -= feefrac;
            }
        }
    }

    /** Update the precomputed data structure to reflect that transaction new_done was added to done. */
    void Done(const Cluster<S>& cluster, const DescendantSets<S>& desc, unsigned new_done) noexcept
    {
#if DEBUG_LINEARIZE
        assert(!m_done[new_done]);
#endif
        m_done.Set(new_done);
        FeeFrac feefrac = cluster[new_done].first;
        for (unsigned i : desc[new_done] / m_done) {
            m_anc_feefracs[i] -= feefrac;
        }
    }

    const FeeFrac& operator[](unsigned i) const noexcept { return m_anc_feefracs[i]; }
};

/** Precomputation data structure for reordering a cluster based on a provided order. */
template<typename S>
struct ReorderedCluster
{
    /** The reordered cluster (both itself and its dependencies) */
    Cluster<S> cluster;
    /** Mapping from the original order (input to constructor) to sorted order. */
    std::vector<unsigned> original_to_sorted;
    /** Mapping back from sorted order to the order given to the constructor. */
    std::vector<unsigned> sorted_to_original;

    /** Given a set with indexes in original order, compute one in sorted order. */
    S OriginalToSorted(const S& val) const noexcept
    {
        S ret;
        for (unsigned i : val) ret.Set(original_to_sorted[i]);
        return ret;
    }

    /** Given a set with indexes in sorted order, compute on in original order. */
    S SortedToOriginal(const S& val) const noexcept
    {
        S ret;
        for (unsigned i : val) ret.Set(sorted_to_original[i]);
        return ret;
    }

    /** Construct a reordered cluster object given a (non-sorted) cluster as input. */
    ReorderedCluster(const Cluster<S>& orig_cluster, std::vector<unsigned> order)
    {
        // Allocate vectors.
        sorted_to_original = std::move(order);
        original_to_sorted.resize(sorted_to_original.size());
        cluster.resize(sorted_to_original.size());
        // Use sorted_to_original to fill original_to_sorted.
        for (size_t i = 0; i < orig_cluster.size(); ++i) {
            original_to_sorted[sorted_to_original[i]] = i;
        }
        // Use sorted_to_original to fill cluster.
        for (size_t i = 0; i < orig_cluster.size(); ++i) {
            cluster[i].first = orig_cluster[sorted_to_original[i]].first;
            cluster[i].second = OriginalToSorted(orig_cluster[sorted_to_original[i]].second);
        }
    }
};

/** Precomputation data structure for sorting a cluster based on individual transaction FeeFrac. */
template<typename S>
struct SortedCluster : public ReorderedCluster<S>
{
private:
    static std::vector<unsigned> SortMapping(const Cluster<S>& orig_cluster)
    {
        std::vector<unsigned> sorted_to_original(orig_cluster.size());
        // Compute sorted_to_original mapping.
        std::iota(sorted_to_original.begin(), sorted_to_original.end(), 0U);
        std::sort(sorted_to_original.begin(), sorted_to_original.end(), [&](unsigned i, unsigned j) {
            if (orig_cluster[i].first == orig_cluster[j].first) {
                return i < j;
            }
            return orig_cluster[i].first > orig_cluster[j].first;
        });
        return sorted_to_original;
    }

public:
    SortedCluster(const Cluster<S>& orig_cluster) : ReorderedCluster<S>(orig_cluster, SortMapping(orig_cluster)) {}
};

/** Given a cluster and its ancestor sets, find the one with the best FeeFrac. */
template<typename S, bool OutputIntermediate = false>
CandidateSetAnalysis<S> FindBestAncestorSet(const Cluster<S>& cluster, const AncestorSets<S>& anc, const AncestorSetFeeFracs<S>& anc_feefracs, const S& done, const S& after)
{
    CandidateSetAnalysis<S> ret;
    ret.max_queue_size = 1;

    for (size_t i = 0; i < cluster.size(); ++i) {
        if (done[i] || after[i]) continue;
        ++ret.iterations;
        ++ret.num_candidate_sets;
        const FeeFrac& feefrac = anc_feefracs[i];
#if DEBUG_LINEARIZE
        assert(!feefrac.IsEmpty());
#endif
        bool new_best = ret.best_candidate_feefrac.IsEmpty();
        if (!new_best) {
            ++ret.comparisons;
            new_best = feefrac > ret.best_candidate_feefrac;
        }
        if (new_best) {
            ret.best_candidate_feefrac = feefrac;
            ret.best_candidate_set = anc[i] / done;
            ret.chosen_transaction = i;
        }
    }

    return ret;
}

#define CANDIDATE_PRESPLIT_ANC

/** An efficient algorithm for finding the best candidate set. Believed to be O(~1.6^n).
 *
 * cluster must be sorted (see SortedCluster) by individual feerate, and anc/desc/done must use
 * the same indexing as cluster.
 */
template<typename S>
CandidateSetAnalysis<S> FindBestCandidateSetEfficient(const Cluster<S>& cluster, const AncestorSets<S>& anc, const DescendantSets<S>& desc, const AncestorSetFeeFracs<S>& anc_feefracs, const S& done, const S& after, uint64_t seed)
{
    /** Data structure with aggregated results. */
    CandidateSetAnalysis<S> ret;
    /** The set of all undecided transactions (everything except done or after). */
    auto todo = S::Fill(cluster.size()) / (done | after);
    // Bail out quickly if we're given a (remaining) cluster that is empty.
    if (todo.None()) return ret;

    /** Type for work queue items.
     *
     * Each consists of:
     * - inc: bitset of transactions definitely included. For every transaction in it, all its
     *        ancestors are also in it. This always includes done.
     * - exc: bitset of transactions definitely excluded. For every transaction in it, all its
     *        descendants are also in it. This always includes after.
     * - pot: the superset of inc, non-overlapping with exc, with the best possible feefrac. It
     *        may include transactions whose ancestors are not all included. It is always a strict
     *        superset of inc (otherwise this work item would be unimprovable, and therefore
     *        should not be in any queue).
     * - inc_feefrac: equal to ComputeSetFeeFrac(cluster, inc / done).
     * - pot_feefrac: equal to ComputeSetFeeFrac(cluster, pot / done). */
    using QueueElem = std::tuple<S, S, S, FeeFrac, FeeFrac>;
    /** Queues with work items. */
    static constexpr unsigned NUM_QUEUES = 1;
    std::deque<QueueElem> queue[NUM_QUEUES];
    /** Sum of total number of queue items across all queues. */
    unsigned queue_tot{0};
    /** Very fast local random number generator. */
    XoRoShiRo128PlusPlus rng(seed);
    /** The best found candidate set so far, including done. */
    S best_candidate;
    /** Equal to ComputeSetFeeFrac(cluster, best_candidate / done). */
    FeeFrac best_feefrac;
    /** Transactions which have feerate > best_feefrac. */
    S imp = todo;
    /** The number of insertions so far into the queues in total. */
    unsigned insert_count{0};

    /** Internal add function.
     *
     * - inc: included set of transactions for new item; must include done and own ancestors.
     * - exc: excluded set of transactions for new item; must include after and own descendants.
     * - pot: superset of inc, non-overlapping with exc, and subset of the new item's pot. The
     *        function will add missing transactions to pot as needed, so it doesn't need to be
     *        the actual new item's pot set.
     * - inc_feefrac: equal to ComputeSetFeeFrac(cluster, inc / done).
     * - pot_feefrac: equal to ComputeSetFeeFrac(cluster, pot / done).
     * - inc_may_be_best: whether the possibility exists that inc_feefrac > best_feefrac.
     * - consider_inc: subset of (pot / inc) to consider adding to inc through jump ahead.
     */
    auto add_fn = [&](const S& init_inc, const S& exc, S pot, FeeFrac inc_feefrac, FeeFrac pot_feefrac, bool inc_may_be_best, S consider_inc) {
        // Add missing entries to pot (and pot_feefrac). We iterate over all undecided transactions
        // excluding pot whose feerate is higher than best_feefrac.
        for (unsigned pos : imp / (pot | exc)) {
            // Determine if adding transaction pos to pot (ignoring topology) would improve it. If
            // not, we're done updating pot.
            if (!pot_feefrac.IsEmpty()) {
                ++ret.comparisons;
                if (!(cluster[pos].first >> pot_feefrac)) break;
            }
            pot_feefrac += cluster[pos].first;
            pot.Set(pos);
            consider_inc.Set(pos);
        }

        // If (pot / done) is empty, this is certainly uninteresting to work on.
        if (pot_feefrac.IsEmpty()) return;

        // If any transaction in consider_inc has only missing ancestors in pot, add it (and its
        // ancestors) to inc. This is legal because any topologically-valid subset of pot must be
        // part of the best possible candidate reachable from this state. To see this:
        // - The feefrac of every element of (pot / inc) is higher than that of (pot / done),
        //   which on its turn is higher than that of (inc / done).
        // - Thus, the feefrac of any non-empty subset of (pot / inc) is higher than that of the
        //   set (inc / done) plus any amount of undecided transactions (including ones in pot).
        // - Let A be a topologically-valid subset of pot, then every transaction in A must be
        //   part of the best candidate reachable from this state:
        //   - Assume A is not a subset of C, the best possible candidate set.
        //   - Then A union C has higher feefrac than C itself.
        //   - But A union C is also topologically valid, as both A and C are.
        //   - That is a contradiction, because we assumed C was the best possible.
        bool updated_inc{false};
        S inc = init_inc;
        // Iterate over all transactions in pot that are not yet included in inc.
        for (unsigned pos : consider_inc) {
            // If that transaction's ancestors are a subset of pot, and the transaction is
            // (still) not part of inc, we can merge it together with its ancestors to inc.
            if (!inc[pos] && (pot >> anc[pos])) {
                inc |= anc[pos];
                updated_inc = true;
            }
        }
        // If anything was added to inc this way, recompute inc_feefrac, remembering that
        // the new inc_feefrac may now be the new best.
        if (updated_inc) {
            inc_feefrac += ComputeSetFeeFrac(cluster, inc / init_inc);
            inc_may_be_best = true;
        }

        // If inc_feefrac may be the new best, check whether it actually is, and if so, update
        // best_feefrac and the associated best_candidate set.
        if (inc_may_be_best) {
            ++ret.num_candidate_sets;
#if DEBUG_LINEARIZE
            assert(!inc_feefrac.IsEmpty());
#endif
            bool new_best = best_feefrac.IsEmpty();
            if (!new_best) {
                ++ret.comparisons;
                new_best = inc_feefrac > best_feefrac;
            }
            if (new_best) {
                best_feefrac = inc_feefrac;
                best_candidate = inc;
                while (imp.Any()) {
                    unsigned check = imp.Last();
                    ++ret.comparisons;
                    if (cluster[check].first >> best_feefrac) break;
                    imp.Reset(check);
                }
            }
        }

        // If no potential transactions exist beyond the already included ones, no improvement
        // is possible anymore.
        if (pot == inc) return;

        // Construct a new work item in one of the queues, in a round-robin fashion, and update
        // statistics.
        queue[insert_count % NUM_QUEUES].emplace_back(std::move(inc), std::move(exc), std::move(pot), std::move(inc_feefrac), std::move(pot_feefrac));
        ++insert_count;
        ++queue_tot;
        ret.max_queue_size = std::max<size_t>(ret.max_queue_size, queue_tot);
    };

    // Find connected components of the cluster, and add queue entries for each which exclude all
    // the other components. This prevents the search further down from considering candidates
    // that span multiple components (as those are necessarily suboptimal).
    auto to_cover = todo;
    while (true) {
        ++ret.iterations;
        // Start with one transaction that hasn't been covered with connected components yet.
        S component;
        component.Set(to_cover.First());
        S added = component;
        // Compute the transitive closure of "is ancestor or descendant of but not done or after".
        while (true) {
            S prev_component = component;
            for (unsigned i : added) {
                component |= anc[i];
                component |= desc[i];
            }
            component /= (done | after);
            if (prev_component == component) break;
            added = component / prev_component;
        }
        auto exclude_others = todo / component;
#ifdef CANDIDATE_PRESPLIT_ANC
        // Find highest ancestor feerate transaction in the component using the precomputed values.
        FeeFrac best_ancestor_feefrac;
        unsigned best_ancestor_tx{0};
        for (unsigned i : component) {
            bool new_best = best_ancestor_feefrac.IsEmpty();
            if (!new_best) {
                ++ret.comparisons;
                new_best = anc_feefracs[i] > best_ancestor_feefrac;
            }
            if (new_best) {
                best_ancestor_tx = i;
                best_ancestor_feefrac = anc_feefracs[i];
            }
        }
        // Add queue entries corresponding to the inclusion and the exclusion of that highest
        // ancestor feerate transaction. This guarantees that regardless of how many iterations
        // are performed later, the best found is always at least as good as the best ancestor set.
        add_fn(done, after | desc[best_ancestor_tx] | exclude_others, done, {}, {}, false, {});
        auto inc{done | anc[best_ancestor_tx]};
        add_fn(inc, after | exclude_others, inc, best_ancestor_feefrac, best_ancestor_feefrac, true, {});
#else
        add_fn(done, after | exclude_others, done, {}, {}, false, {});
#endif
        // Update the set of transactions to cover, and finish if there are none left.
        to_cover /= component;
        if (to_cover.None()) break;
    }

    // Work processing loop.
    while (queue_tot) {
        // Find a queue to pop a work item from.
        unsigned queue_idx;
        do {
            queue_idx = rng() % NUM_QUEUES;
        } while (queue[queue_idx].empty());

        // Move the work item from the queue to local variables, popping it.
        auto [inc, exc, pot, inc_feefrac, pot_feefrac] = std::move(queue[queue_idx].front());
        queue[queue_idx].pop_front();
        --queue_tot;

        // If this item's potential feefrac is not better than the best seen so far, drop it.
        if (!best_feefrac.IsEmpty()) {
            ++ret.comparisons;
            if (pot_feefrac <= best_feefrac) continue;
        }

        ++ret.iterations;

        // Decide which transaction to split on (create new work items; one with it included, one
        // with it excluded).
        //
        // Among the (undecided) ancestors of the highest individual feefrac transaction, pick the
        // one which reduces the search space most:
        // - Minimizes the size of the largest of the undecided sets after including or excluding.
        // - If the above is equal, the one that minimizes the other branch's undecided set size.
        // - If the above are equal, the one with the best individual feefrac.
        unsigned pos = 0;
        auto remain = todo / inc;
        remain /= exc;
        unsigned first = remain.First();
        auto select = remain & anc[first];
        std::optional<std::pair<unsigned, unsigned>> pos_counts;
        for (unsigned i : select) {
            std::pair<unsigned, unsigned> counts{(remain / anc[i]).Count(), (remain / desc[i]).Count()};
            if (counts.first < counts.second) std::swap(counts.first, counts.second);
            if (!pos_counts.has_value() || counts < *pos_counts) {
                pos = i;
                pos_counts = counts;
            }
        }
        if (!pos_counts.has_value()) continue;

        // Consider adding a work item corresponding to that transaction excluded. As nothing is
        // being added to inc, this new entry cannot be a new best.
        add_fn(/*init_inc=*/inc,
               /*exc=*/exc | desc[pos],
               /*pot=*/pot / desc[pos],
               /*inc_feefrac=*/inc_feefrac,
               /*pot_feefrac=*/pot_feefrac - ComputeSetFeeFrac(cluster, pot & desc[pos]),
               /*inc_may_be_best=*/false,
               /*consider_inc=*/{});

        // Consider adding a work item corresponding to that transaction included. Since only
        // connected subgraphs can be optimal candidates, if there is no overlap between the
        // parent's included transactions (inc) and the ancestors of the newly added transaction
        // (outside of done), we know it cannot possibly be the new best.
        // One exception to this is the first addition after an empty inc (inc=done). However,
        // due to the preseeding with the best ancestor set, we know that anything better must
        // necessarily consist of the union of at least two ancestor sets, and this is not a
        // concern.
        add_fn(/*init_inc=*/inc | anc[pos],
               /*exc=*/exc,
               /*pot=*/pot | anc[pos],
               /*inc_feefrac=*/inc_feefrac + ComputeSetFeeFrac(cluster, anc[pos] / inc),
               /*pot_feefrac=*/pot_feefrac + ComputeSetFeeFrac(cluster, anc[pos] / pot),
#ifdef CANDIDATE_PRESPLIT_ANC
               /*inc_may_be_best=*/!(done >> (inc & anc[pos])),
#else
               /*inc_may_be_best=*/!(done >> (inc & anc[pos])) || (done == inc),
#endif
               /*consider_inc=*/pot / inc);
    }

    // Return the best seen candidate set.
    ret.best_candidate_set = best_candidate / done;
    ret.best_candidate_feefrac = best_feefrac;
    return ret;
}

template<typename S>
std::vector<std::pair<FeeFrac, S>> ChunkLinearization(const Cluster<S>& cluster, Span<const unsigned> linearization)
{
    std::vector<std::pair<FeeFrac, S>> chunks;
    chunks.reserve(linearization.size());
    for (unsigned i : linearization) {
        S add;
        add.Set(i);
        FeeFrac add_feefrac = cluster[i].first;
        while (!chunks.empty() && add_feefrac >> chunks.back().first) {
            add |= chunks.back().second;
            add_feefrac += chunks.back().first;
            chunks.pop_back();
        }
        chunks.emplace_back(add_feefrac, add);
    }
    return chunks;
}

/** Given a cluster and a linearization for it, improve the linearization such that its chunks are
 *  all connected. It may also result in improved sub-chunk ordering.
 *
 * O(n^2) in the size of the cluster in the worst case. If the input linearization is the output
 * of PostLinearization itself, runtime is O(n). */
template<typename S, bool Rev = false>
void PostLinearization(const Cluster<S>& cluster, std::vector<unsigned>& linearization, uint64_t* swaps = nullptr)
{
    struct Entry {
        /** data index for previous transaction in this chunk (cyclic). */
        unsigned prev_tx;
        // The following fields are only relevant for the heads of chunks:
        /** - data index for the head of the previous chunk (cyclic). */
        unsigned prev_chunk;
        /** - the chunk feerate. */
        FeeFrac chunk_feerate;
        /** - the set of all chunk members */
        S chunk;
        /** - the set of all chunk parents */
        S parents;
    };
    /** data[i+1] contains information about transaction 'i'. data[0] is a sentinel. */
    std::vector<Entry> data(cluster.size() + 1);
    data[0].prev_tx = 0;
    data[0].prev_chunk = 0;
    uint64_t num_swaps = 0;
    for (unsigned lp = 0; lp < linearization.size(); ++lp) {
        unsigned i = linearization[Rev ? linearization.size() - 1 - lp : lp];
        // Create a new chunk with just transaction 'i' at the end.
        auto& entry = data[i + 1];
        entry.prev_tx = i + 1;
        entry.prev_chunk = data[0].prev_chunk;
        data[0].prev_chunk = i + 1;
        entry.chunk_feerate = cluster[i].first;
        assert(entry.chunk.None());
        entry.chunk.Set(i);
        entry.parents = cluster[i].second;
        // 'after_work' is the head of the chunk *after* the one we're working on.
        // We start working on the newly inserted chunk, so after_work starts at the sentinel.
        unsigned after_work = 0;
        while (true) {
            unsigned work = data[after_work].prev_chunk;
            assert(work != 0); // cannot work on the sentinel
            unsigned before_work = data[work].prev_chunk;
            // If the previous chunk is the sentinel, we are done.
            if (before_work == 0) break;
            // If the previous chunk has higher or equal feerate, we are done.
            if constexpr (Rev) {
                if (!(data[before_work].chunk_feerate >> data[work].chunk_feerate)) break;
            } else {
                if (!(data[before_work].chunk_feerate << data[work].chunk_feerate)) break;
            }
            // Check whether there is a dependency on the previous chunk.
            if (Rev ? (data[before_work].parents && data[work].chunk) : (data[work].parents && data[before_work].chunk)) {
                // There is a dependency; merge the chunk data.
                data[before_work].chunk_feerate += data[work].chunk_feerate;
                data[before_work].chunk |= data[work].chunk;
                data[before_work].parents = (data[before_work].parents | data[work].parents) / data[before_work].chunk;
                // Stitch the two chunks together.
                std::swap(data[before_work].prev_tx, data[work].prev_tx);
                // Continue with the now-merged chunk.
                data[after_work].prev_chunk = before_work;
            } else {
                // There is no dependency; swap the two chunks.
                data[after_work].prev_chunk = before_work;
                data[work].prev_chunk = data[before_work].prev_chunk;
                data[before_work].prev_chunk = work;
                // Continue with the now-moved previous work chunk.
                after_work = before_work;
                ++num_swaps;
            }
        }
    }
    // Iterate over the chunks, and their transactions, overwriting linearization backwards.
    unsigned lp = 0;
    unsigned work_chunk = data[0].prev_chunk;
    while (work_chunk != 0) {
        unsigned first_tx = work_chunk;
        unsigned work_tx = first_tx;
        do {
            work_tx = data[work_tx].prev_tx;
            assert(work_tx != 0);
            assert(lp != linearization.size());
            linearization[Rev ? lp : linearization.size() - 1 - lp] = work_tx - 1;
            ++lp;
        } while (work_tx != first_tx);
        work_chunk = data[work_chunk].prev_chunk;
    }
    assert(lp == linearization.size());
    if (swaps) *swaps = num_swaps;
}

/** Given two linearizations for the same cluster, return a new linearization that better or equal than both.
 *
 * The implemented algorithm is prefix-intersection merging, equivalent to:
 * - While not all transactions are included:
 *   - Find P_1, the highest-feerate prefix of L_1 (ignoring already included transactions).
 *   - Find P_2, the highest-feerate prefix of L_2 (ignoring already included transactions).
 *   - Let i be such that P_i is the higher-feerate of the two.
 *   - Find C, the highest-feerate prefix of the intersection between L_{3-i} with P_i.
 *   - Include the transactions from C in the output, and start over.
 *
 * Only transactions that appear in both linearizations will be in the output.
 *
 * Worst-case complexity is O(n^2) in the number of transactions, but merging identical
 * linearizations is only O(n).
 *
 * For discussion, see https://delvingbitcoin.org/t/merging-incomparable-linearizations/209.
 */
template<typename S>
std::vector<unsigned> MergeLinearizations(const Cluster<S>& cluster, Span<const unsigned> lin1, Span<const unsigned> lin2)
{
    std::vector<unsigned> ret;
    ret.reserve(std::min(lin1.size(), lin2.size()));
    /** Indices within cluster that are done. */
    S done;
    /** Indices within lin1 (not within cluster!) that are still todo. */
    S todo1 = S::Fill(lin1.size());
    /** Indices within lin2 (not within cluster!) that are still todo. */
    S todo2 = S::Fill(lin2.size());

    /** Find the first remaining transaction in a linearization (also update todo). */
    auto first_tx = [&](Span<const unsigned> lin, S& todo) -> std::pair<unsigned, unsigned> {
        S new_todo = todo;
        for (unsigned i : todo) {
            // Find the index into cluster for that position.
            unsigned idx = lin[i];
            // If that index has not been included, return it;
            if (!done[idx]) {
                todo = new_todo;
                return {idx, i};
            }
            // Otherwise remove it from todo.
            new_todo.Reset(i);
        }
        return {(unsigned)(-1), 0};
    };

    /** Find the prefix of lin that has the highest feerate (also update todo). */
    auto first_chunk = [&](Span<const unsigned> lin, S& todo) -> std::pair<S, FeeFrac> {
        FeeFrac sum, best_sum;
        S set, best_set;
        S new_todo = todo;
        // Iterate over the remaining positions in lin (note that todo can be out of date).
        for (unsigned i : todo) {
            // Find the index into cluster for that position.
            unsigned idx = lin[i];
            // If that index has since been included, update todo, and skip it.
            if (done[idx]) {
                new_todo.Reset(i);
                continue;
            }
            // Update running sum/set of unincluded prefixes.
            sum += cluster[idx].first;
            set.Set(idx);
            // If this is a new best sum, remember it.
            if (best_sum.IsEmpty() || sum >> best_sum) {
                best_sum = sum;
                best_set = set;
            }
        }
        // Remember the updated todo, and return the best set of cluster indices we found.
        todo = new_todo;
        return {best_set, best_sum};
    };

    /** Find the highest-feerate prefix of lin, restricted to indices in filter. */
    auto best_subset = [&](Span<const unsigned> lin, const S& todo, const S& filter) -> std::pair<S, S> {
        FeeFrac sum, best_sum;
        S set, best_set, select, best_select;
        // Iterate over the unincluded positions in lin (todo is necessarily up to date here).
        for (unsigned i : todo) {
            unsigned idx = lin[i];
            // If the cluster index in that position is in the filter, process it.
            if (filter[idx]) {
                // Update running sum/set/select (set contains cluster indices, select lin indices).
                sum += cluster[idx].first;
                set.Set(idx);
                select.Set(i);
                // If this is a new best sum, remember it.
                if (best_sum.IsEmpty() || sum >> best_sum) {
                    best_sum = sum;
                    best_set = set;
                    best_select = select;
                }
                // Optimization: if all filter entries have been processed, nothing more can be added.
                if (set == filter) break;
            }
        }
        // Return the best lin indices and cluster indices.
        return {best_select, best_set};
    };

    while (true) {
        // Find the first remaining transaction in both linearizations.
        auto [tx1, pos1] = first_tx(lin1, todo1);
        auto [tx2, pos2] = first_tx(lin2, todo2);
        // If either has run out, we're done.
        if (tx1 == (unsigned)(-1) || tx2 == (unsigned)(-1)) break;
        // As an optimization, see if those transactions are identical. If so, just copy it to the
        // output directly.
        if (tx1 == tx2) {
            ret.push_back(tx1);
            done.Set(tx1);
            todo1.Reset(pos1);
            todo2.Reset(pos2);
            continue;
        }
        // If not, find best prefix in both linearizations.
        auto [chunk1, feerate1] = first_chunk(lin1, todo1);
        auto [chunk2, feerate2] = first_chunk(lin2, todo2);
        // Find best prefix of the intersection of that prefix with the other linearization,
        // and then include that. The indirection through select is used so that the output
        // is in the order of the linearization it was taken from (which is always topological).
        if (feerate2 >= feerate1) {
            auto [select, best] = best_subset(lin1, todo1, chunk2);
            done |= best;
            for (unsigned i : select) ret.push_back(lin1[i]);
            todo1 /= select;
        } else {
            auto [select, best] = best_subset(lin2, todo2, chunk1);
            done |= best;
            for (unsigned i : select) ret.push_back(lin2[i]);
            todo2 /= select;
        }
    }

    return ret;
}

struct LinearizationResult
{
    std::vector<unsigned> linearization;
    size_t iterations{0};
    size_t comparisons{0};
};

#if 0
[[maybe_unused]] std::ostream& operator<<(std::ostream& o, const FeeFrac& data)
{
    o << "(" << data.fee << "/" << data.size << "=" << ((double)data.fee / data.size) << ")";
    return o;
}

[[maybe_unused]] std::ostream& operator<<(std::ostream& o, Span<const unsigned> data)
{
    o << '{';
    bool first = true;
    for (unsigned i : data) {
        if (first) {
            first = false;
        } else {
            o << ',';
        }
        o << i;
    }
    o << '}';
    return o;
}

template<typename I>
std::ostream& operator<<(std::ostream& s, const bitset_detail::IntBitSet<I>& bs)
{
    s << "[";
    size_t cnt = 0;
    for (size_t i = 0; i < bs.Size(); ++i) {
        if (bs[i]) {
            if (cnt) s << ",";
            ++cnt;
            s << i;
        }
    }
    s << "]";
    return s;
}

template<typename I, unsigned N>
std::ostream& operator<<(std::ostream& s, const bitset_detail::MultiIntBitSet<I, N>& bs)
{
    s << "[";
    size_t cnt = 0;
    for (size_t i = 0; i < bs.Size(); ++i) {
        if (bs[i]) {
            if (cnt) s << ",";
            ++cnt;
            s << i;
        }
    }
    s << "]";
    return s;
}

/** String serialization for debug output of Cluster. */
template<typename S>
std::ostream& operator<<(std::ostream& o, const Cluster<S>& cluster)
{
    o << "Cluster{";
    for (size_t i = 0; i < cluster.size(); ++i) {
        if (i) o << ",";
        o << i << ":" << cluster[i].first << cluster[i].second;
    }
    o << "}";
    return o;
}
#endif

/** Compute a full linearization of a cluster using ancestor-based sort. */
template<typename S>
LinearizationResult LinearizeClusterAnc(const Cluster<S>& cluster)
{
    LinearizationResult ret;
    ret.linearization.reserve(cluster.size());
    AncestorSets<S> anc(cluster);
    DescendantSets<S> desc(anc);
    std::vector<unsigned> anccount(cluster.size(), 0);
    for (unsigned i = 0; i < cluster.size(); ++i) {
        anccount[i] = anc[i].Count();
    }
    AncestorSetFeeFracs anc_feefracs(cluster, anc, {});
    auto all = S::Fill(cluster.size());
    S done;

    while (done != all) {
        auto analysis = FindBestAncestorSet(cluster, anc, anc_feefracs, done, {});
        ret.iterations += analysis.iterations;
        ret.comparisons += analysis.comparisons;

        size_t old_size = ret.linearization.size();
        for (unsigned selected : analysis.best_candidate_set) {
            ret.linearization.emplace_back(selected);
        }
        std::sort(ret.linearization.begin() + old_size, ret.linearization.end(), [&](unsigned a, unsigned b) {
            if (anccount[a] == anccount[b]) return a < b;
            return anccount[a] < anccount[b];
        });

        // Update bookkeeping
        done |= analysis.best_candidate_set;
        anc_feefracs.Done(cluster, desc, analysis.best_candidate_set);
    }

    return ret;
}

/** Compute a full linearization of a cluster (vector of cluster indices). */
template<typename S>
LinearizationResult LinearizeCluster(const Cluster<S>& cluster, unsigned optimal_limit, uint64_t seed)
{
    LinearizationResult ret;
    ret.linearization.reserve(cluster.size());
    auto all = S::Fill(cluster.size());
    S done;
    unsigned left = (all / done).Count();

    /** Very fast local random number generator. */
    XoRoShiRo128PlusPlus rng(seed);

    // Precompute stuff.
    SortedCluster<S> sorted(cluster);
    AncestorSets<S> anc(sorted.cluster);
    DescendantSets<S> desc(anc);
    // Precompute ancestor set sizes, to help with topological sort.
    std::vector<unsigned> anccount(cluster.size(), 0);
    for (unsigned i = 0; i < cluster.size(); ++i) {
        anccount[i] = anc[i].Count();
    }
    AncestorSetFeeFracs anc_feefracs(sorted.cluster, anc, {});

    while (done != all) {
        // Find candidate set.
        CandidateSetAnalysis<S> analysis;
        if (left > optimal_limit) {
            analysis = FindBestAncestorSet(sorted.cluster, anc, anc_feefracs, done, {});
        } else {
            analysis = FindBestCandidateSetEfficient(sorted.cluster, anc, desc, anc_feefracs, done, {}, rng() ^ ret.iterations);
        }

        // Sanity checks.
#if DEBUG_LINEARIZE
        assert(analysis.best_candidate_set.Any()); // Must be at least one transaction
        assert(!(analysis.best_candidate_set && done)); // Cannot overlap with processed ones.
#endif

        // Update statistics.
        ret.iterations += analysis.iterations;
        ret.comparisons += analysis.comparisons;

        // Append candidate's transactions to linearization, and topologically sort them.
        size_t old_size = ret.linearization.size();
        for (unsigned selected : analysis.best_candidate_set) {
            ret.linearization.emplace_back(selected);
        }
        std::sort(ret.linearization.begin() + old_size, ret.linearization.end(), [&](unsigned a, unsigned b) {
            if (anccount[a] == anccount[b]) return a < b;
            return anccount[a] < anccount[b];
        });

        // Update bookkeeping
        done |= analysis.best_candidate_set;
        left -= analysis.best_candidate_set.Count();
        anc_feefracs.Done(sorted.cluster, desc, analysis.best_candidate_set);
    }

    // Map linearization back from sorted cluster indices to original indices.
    for (unsigned i = 0; i < cluster.size(); ++i) {
        ret.linearization[i] = sorted.sorted_to_original[ret.linearization[i]];
    }

    return ret;
}

#if 0
uint8_t ReadSpanByte(Span<const unsigned char>& data)
{
    if (data.empty()) return 0;
    uint8_t val = data[0];
    data = data.subspan(1);
    return val;
}

/** Deserialize a number, in little-endian 7 bit format, top bit set = more size. */
uint64_t DeserializeNumberBase128(Span<const unsigned char>& data)
{
    uint64_t ret{0};
    for (int i = 0; i < 10; ++i) {
        uint8_t b = ReadSpanByte(data);
        ret |= ((uint64_t)(b & uint8_t{0x7F})) << (7 * i);
        if ((b & 0x80) == 0) break;
    }
    return ret;
}
#endif

/** Serialize a number, in little-endian 7 bit format, top bit set = more size. */
void SerializeNumberBase128(uint64_t val, std::vector<unsigned char>& data)
{
    for (int i = 0; i < 10; ++i) {
        uint8_t b = (val >> (7 * i)) & 0x7F;
        val &= ~(uint64_t{0x7F} << (7 * i));
        if (val) {
            data.push_back(b | 0x80);
        } else {
            data.push_back(b);
            break;
        }
    }
}

/** Serialize a cluster in the following format:
 *
 * - For every transaction:
 *   - Base128 encoding of its byte size (at least 1, max 2^22-1).
 *   - Base128 encoding of its fee in fee (max 2^51-1).
 *   - For each of its direct parents:
 *     - If parent_idx < child_idx:
 *       - Base128 encoding of (child_idx - parent_idx)
 *     - If parent_idx > child_idx:
 *       - Base128 encoding of (parent_idx)
 *   - A zero byte
 * - A zero byte
 */
template<typename S>
void SerializeCluster(const Cluster<S>& cluster, std::vector<unsigned char>& data)
{
    for (unsigned i = 0; i < cluster.size(); ++i) {
        SerializeNumberBase128(cluster[i].first.size, data);
        SerializeNumberBase128(cluster[i].first.fee, data);
        for (unsigned j = 1; j <= i; ++j) {
            if (cluster[i].second[i - j]) SerializeNumberBase128(j, data);
        }
        for (unsigned j = i + 1; j < cluster.size(); ++j) {
            if (cluster[i].second[j]) SerializeNumberBase128(j, data);
        }
        data.push_back(0);
    }
    data.push_back(0);
}

/** Deserialize a cluster in the same format as SerializeCluster (overflows wrap). */
#if 0
template<typename S>
Cluster<S> DeserializeCluster(Span<const unsigned char>& data)
{
    Cluster<S> ret;
    while (true) {
        int32_t size = DeserializeNumberBase128(data) & 0x3fffff;
        if (size == 0) break;
        int64_t fee = DeserializeNumberBase128(data) & 0x7ffffffffffff;
        S parents;
        while (true) {
            unsigned read = DeserializeNumberBase128(data);
            if (read == 0) break;
            if (read <= ret.size() && ret.size() < S::Size() + read) {
                parents.Set(ret.size() - read);
            } else {
                if (read < S::Size()) {
                    parents.Set(read);
                }
            }
        }
        ret.emplace_back(FeeFrac{fee, size}, std::move(parents));
    }
    S all = S::Fill(std::min<unsigned>(ret.size(), S::Size()));
    for (unsigned i = 0; i < ret.size(); ++i) {
        ret[i].second &= all;
    }
    return ret;
}
#endif

/** Minimize the set of parents of every cluster transaction, without changing ancestry. */
template<typename S>
void WeedCluster(Cluster<S>& cluster, const AncestorSets<S>& ancs)
{
    std::vector<std::pair<unsigned, unsigned>> mapping(cluster.size());
    for (unsigned i = 0; i < cluster.size(); ++i) {
        mapping[i] = {ancs[i].Count(), i};
    }
    std::sort(mapping.begin(), mapping.end());
    for (unsigned i = 0; i < cluster.size(); ++i) {
        const auto& [_anc_count, idx] = mapping[i];
        S parents;
        S cover;
        cover.Set(idx);
        for (unsigned j = 0; j < i; ++j) {
            const auto& [_anc_count_j, idx_j] = mapping[i - 1 - j];
            if (ancs[idx][idx_j] && !cover[idx_j]) {
                parents.Set(idx_j);
                cover |= ancs[idx_j];
            }
        }
#if DEBUG_LINEARIZE
        assert(cover == ancs[idx]);
#endif
        cluster[idx].second = std::move(parents);
    }
}

/** Construct a new cluster with done removed (leaving the rest in order). */
template<typename S>
Cluster<S> TrimCluster(const Cluster<S>& cluster, const S& done)
{
    Cluster<S> ret;
    std::vector<unsigned> mapping;
    mapping.resize(cluster.size());
    ret.reserve(cluster.size() - done.Count());
    for (unsigned idx : S::Fill(cluster.size()) / done) {
        mapping[idx] = ret.size();
        ret.push_back(cluster[idx]);
    }
    for (unsigned i = 0; i < ret.size(); ++i) {
        S parents;
        for (unsigned idx : ret[i].second / done) {
            parents.Set(mapping[idx]);
        }
        ret[i].second = std::move(parents);
    }
    return ret;
}

/** Minimize a cluster, and serialize to byte vector. */
template<typename S>
std::vector<unsigned char> DumpCluster(Cluster<S> cluster)
{
    AncestorSets<S> anc(cluster);
    WeedCluster(cluster, anc);
    std::vector<unsigned char> data;
    SerializeCluster(cluster, data);
    data.pop_back();
    return data;
}

/** Test whether an ancestor set was computed from an acyclic cluster. */
template<typename S>
bool IsAcyclic(const AncestorSets<S>& anc)
{
    for (unsigned i = 0; i < anc.Size(); ++i) {
        // Determine if there is a j<i which i has as ancestor, and which has i as ancestor.
        for (unsigned j : anc[i]) {
            if (j >= i) break;
            if (anc[j][i]) return false;
        }
    }
    return true;
}


} // namespace

} // namespace linearize_cluster

#endif // BITCOIN_CLUSTER_LINEARIZE_H
