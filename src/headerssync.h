// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HEADERS_SYNC_H
#define BITCOIN_HEADERS_SYNC_H

#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <net.h> // For NodeId
#include <consensus/params.h>
#include <util/hasher.h>
#include <util/bitdeque.h>

#include <vector>
#include <deque>

struct CCompressedHeader;

/** HeadersSyncState:
 *
 * We wish to download a peer's headers chain in a DoS-resistant way.
 *
 * The Bitcoin protocol does not offer an easy way to determine the work on a
 * peer's chain. Currently, we can query a peer's headers by using a GETHEADERS
 * message, and our peer can return a set of up to 2000 headers that connect to
 * something we know. If a peer's chain has more than 2000 blocks, then we need
 * a way to verify that the chain actually has enough work on it to be useful to
 * us -- by being above our anti-DoS minimum-chain-work threshold -- before we
 * commit to storing those headers in memory. Otherwise, it would be cheap for
 * an attacker to waste all our memory by serving us low-work headers
 * (particularly for a new node coming online for the first time).
 *
 * To prevent memory-DoS with low-work headers, while still always being
 * able to reorg to whatever the most-work chain is, we require that a chain
 * meet a work threshold before committing it to memory. We can do this by
 * downloading a peer's headers twice, whenever we are not sure that the chain
 * has sufficient work:
 *
 * - In the first download phase, we can calculate the work on the chain as we
 * go (just by checking the nBits value on each header, and validating the
 * proof-of-work).
 *
 * - Once we have reached a header where the cumulative chain work is
 * sufficient, we switch to downloading the headers a second time, this time
 * storing them in memory.
 *
 * To prevent an attacker from using (eg) the honest chain to convince us that
 * they have a high-work chain, but then feeding us an alternate set of
 * low-difficulty headers in the second phase, we store commitments to the
 * chain we see in the first download phase that we check in the second phase,
 * as follows:
 *
 * - In phase 1, store 1 bit (using a salted hash function) for every N headers
 * that we see. With a reasonable choice of N, this uses relatively little
 * memory even for a very long chain.
 *
 * - In phase 2 (redownload), keep a lookahead buffer of size H, and only
 * accept a batch of N (N < H) headers to memory once we've verified that H/N =
 * S commitments have all passed verification. With this parametrization, we
 * can achieve a given security target (S) while choosing H and N to minimize
 * memory usage in this scheme.
 */

class HeadersSyncState {
public:
    HeadersSyncState(NodeId id, const Consensus::Params& consensus_params);
    ~HeadersSyncState() {}

    enum class State {
        /** INITIAL_DOWNLOAD means the peer has not yet demonstrated their
         * chain has sufficient work */
        INITIAL_DOWNLOAD,
        /** REDOWNLOAD means the peer has given us a high-enough-work chain,
         * and now we're redownloading the headers we saw before and trying to
         * accept them */
        REDOWNLOAD,
        /** We're done syncing with this peer and can discard any remaining state */
        FINAL
    };

    /** Return the current state of our download */
    State GetState() const { return m_download_state; }

    /** Start headers sync (via this download-twice mechanism)
     * chain_start: best known fork point that the peer's headers branch from
     * initial_headers: first batch of headers to process
     * minimum_required_work: amount of chain work required to accept the chain
     */
    std::optional<CBlockLocator> StartInitialDownload(const CBlockIndex* chain_start, const
            std::vector<CBlockHeader>& initial_headers, const arith_uint256&
            minimum_required_work, CBlockLocator&& chain_start_locator);

    /** Process a batch of headers, once a sync via this mechanism has started
     *
     * headers: headers that were received over the network for processing
     * full_headers_message: true if the message was at max capacity,
     *                       indicating more headers may be available
     * headers_to_process: will be filled in with any headers that the caller
     *                     can process and validate now (because these returned
     *                     headers are on a chain with sufficient work)
     * processing_success: set to false if an error is detected and the sync is
     *                     aborted; true otherwise.
     */
    std::optional<CBlockLocator> ProcessNextHeaders(const std::vector<CBlockHeader>& headers,
            bool full_headers_message, std::vector<CBlockHeader>&
            headers_to_process, bool &processing_success);

private:
    /** Clear out all download state that might be in progress (freeing any used
     * memory), and mark this object as no longer usable.
     */
    void Finalize();

    /**
     *  Only called in INITIAL_DOWNLOAD.
     *  Validate the work on the headers we received from the network, and
     *  store commitments for later. Update overall state with successfully
     *  processed headers.
     *  On failure, this invokes Finalize() and returns false.
     */
    bool ValidateAndStoreHeadersCommitments(const std::vector<CBlockHeader>& headers);

    /** In INITIAL_DOWNLOAD, process and update state for a single header */
    bool ValidateAndProcessSingleHeader(const CBlockHeader& previous, const
            CBlockHeader& current, int64_t current_height);

    /** In REDOWNLOAD, check a header's commitment (if applicable) and add to
     * buffer for later processing */
    bool ValidateAndStoreRedownloadedHeader(const CBlockHeader& header);

    /** Return a set of headers that satisfy our proof-of-work threshold */
    std::vector<CBlockHeader> RemoveHeadersReadyForAcceptance();

    /** Issue the next GETHEADERS message to our peer */
    std::optional<CBlockLocator> MakeNextHeadersRequest();

private:
    /** NodeId of the peer (used for log messages) **/
    const NodeId m_id;

    /** We use the consensus params in our anti-DoS calculations */
    const Consensus::Params& m_consensus_params;

    /** Store the last block in our block index that the peer's chain builds from */
    const CBlockIndex* m_chain_start{nullptr};

    /** Cache the block locator for m_chain_start, since we use this in every
     * getheaders request */
    CBlockLocator m_chain_start_locator;

    /** Minimum work that we're looking for on this chain. */
    arith_uint256 m_minimum_required_work;

    /** Work that we've seen so far on the peer's chain */
    arith_uint256 m_current_chain_work;

    /**
     * m_hasher is a salted hasher for making our 1-bit commitments to headers
     * we've seen.
     * m_header_commitments is where we store these 1-bit commitments.
     * m_max_commitments is a bound we calculate on how long an honest peer's
     * chain could be, given the MTP rule. Any peer giving us more headers than
     * this will have its sync aborted. This serves as a memory bound on
     * m_header_commitments.
     */
    SaltedTxidHasher m_hasher;
    bitdeque<> m_header_commitments;
    uint64_t m_max_commitments{0}; // calculated at start of sync based on age of chain.

    /** Store the latest header received while in INITIAL_DOWNLOAD */
    CBlockHeader m_last_header_received;

    /** Height of m_last_header_received */
    int64_t m_current_height{0}; // height of last header received

    /** Once we've gotten to a target block with sufficient work, save it for
     *  later.
     */
    uint256 m_blockhash_with_sufficient_work;

    /** During phase 2 (REDOWNLOAD), we buffer redownloaded headers in memory
     *  until enough commitments have been verified; those are stored in
     *  m_redownloaded_headers */
    std::deque<CCompressedHeader> m_redownloaded_headers;

    /** Height of last header in m_redownloaded_headers */
    int64_t m_redownload_buffer_last_height{0};

    /** Hash of last header in m_redownloaded_headers (we have to cache it
     * because we don't have hashPrevBlock available in a CCompressedHeader)
     */
    uint256 m_redownload_buffer_last_hash;

    /** The hashPrevBlock entry for the first header in m_redownloaded_headers
     * We need this to reconstruct the full header when it's time for
     * processing.
     */
    uint256 m_redownload_buffer_first_prev_hash;

    /** Set this to true once we encounter the target blockheader during phase
     * 2 (REDOWNLOAD). At this point, we can process and store all remaining
     * headers still in m_redownloaded_headers.
     */
    bool m_process_all_remaining_headers{false};

    /** Current state of our headers sync. */
    State m_download_state{State::INITIAL_DOWNLOAD};
};

// A compressed CBlockHeader, which leaves out the prevhash
struct CCompressedHeader {
    // header
    int32_t nVersion{0};
    uint256 hashMerkleRoot;
    uint32_t nTime{0};
    uint32_t nBits{0};
    uint32_t nNonce{0};

    CCompressedHeader()
    {
        hashMerkleRoot.SetNull();
    }

    CCompressedHeader(const CBlockHeader& header)
    {
        nVersion = header.nVersion;
        hashMerkleRoot = header.hashMerkleRoot;
        nTime = header.nTime;
        nBits = header.nBits;
        nNonce = header.nNonce;
    }

    CBlockHeader GetFullHeader(const uint256& hash_prev_block) {
        CBlockHeader ret;
        ret.nVersion = nVersion;
        ret.hashPrevBlock = hash_prev_block;
        ret.hashMerkleRoot = hashMerkleRoot;
        ret.nTime = nTime;
        ret.nBits = nBits;
        ret.nNonce = nNonce;
        return ret;
    };
};

#endif // BITCOIN_HEADERS_SYNC_H
