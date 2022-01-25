//#include <assert>
#include <iostream>
#include "dbwrapper.h"
#include "uint256.h"
#include "coins.h"
#include "validation.h"
#include "hash.h"

using namespace std;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

int main(int argc, char **argv)
{
    std::stringstream rawoutput;
    std::stringstream fmtoutput;

    for (int i=1; i<argc; ++i) {
        CDBWrapper db(DBParams{argv[i], 1<<23, false, false, false});

        CDBIterator* it = db.NewIterator();
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            std::string strKey, strValue;
            it->GetKey(strKey);
            it->GetValue(strValue);
            rawoutput << strKey << strValue;
            DataStream ssKey(MakeUCharSpan(strKey));
            DataStream ssValue(MakeUCharSpan(strValue));
            // Chainstate uses two types of entries:
            // 1) B: hash (hash of the last block in active chain)
            // 2) c<txid>: <ccoins>
            if (strKey == "B") {
                uint256 hashBestChain;
                ssValue >> hashBestChain;
                fmtoutput << "B: " << hashBestChain.GetHex() << endl;
            } else if (strKey.at(0) == 'c') {
                uint256 txhash;
                std::pair<uint8_t, uint256> p;
                ssKey >> p;
                fmtoutput << p.first << p.second.GetHex() << ": ";
                //CCoins coins;
                //ssValue >> coins;
                //fmtoutput << coins.fCoinBase << coins.nHeight << coins.nVersion;
                //uint256 runHash = 0;
                //BOOST_FOREACH(const CTxOut &txout, coins.vout) {
                //    if (!txout.IsNull()) {
                //        uint256 curHash = txout.GetHash();
                //        runHash = Hash(runHash.begin(), runHash.end(), curHash.begin(), curHash.end());
                //    }
                // }

                fmtoutput << Hash(MakeUCharSpan(strValue)).GetHex();
                fmtoutput << endl;
            } // blockindex uses five types of entries:
            // 1) b<blockhash>: <cdiskblockindex>
            // 2) f<file number>: <cblockfileinfo>
            // 3) l: <file number> (last file)
            // 4) R: 1 (entry exists when reindexing)
            // 5) F<flag>: {0,1} (setting a bool flag)
            else if (strKey.at(0) == 'b') {
                std::pair<uint8_t, uint256> p;
                ssKey >> p;
                fmtoutput << p.first << p.second.GetHex();
                CDiskBlockIndex cdbi;
                ssValue >> cdbi;
                fmtoutput << ": " << cdbi.hashPrev.GetHex();
                uint256 blockhash = cdbi.ConstructBlockHash();
                if (blockhash != p.second)
                    fmtoutput << "," << blockhash.GetHex();
                fmtoutput << endl;
            } else if (strKey.at(0) == 'f') {
                std::pair<uint8_t, uint8_t> p;
                ssKey >> p;
                fmtoutput << p.first << p.second;
                CBlockFileInfo cbfi;
                ssValue >> cbfi;
                fmtoutput << ": " << cbfi.ToString() << endl;
            } else if (strKey == "l") {
                int nFile;
                ssValue >> nFile;
                fmtoutput << strKey << ": " << nFile << endl;
            } else if (strKey == "R") {
                uint8_t reindex;
                ssValue >> reindex;
                fmtoutput << strKey << ": " << reindex << endl;
            } else if (strKey.at(0) == 'F') {
                std::pair<uint8_t, std::string> p;
                ssKey >> p;
                uint8_t value;
                ssValue >> value;
                fmtoutput << p.first << p.second << ": " << value << endl;
            } else {
                fmtoutput << strKey << ": "  << strValue << endl;
            }
        }
        delete it;
    }
    //  assert(it->status().ok());  // Check for any errors found during the scan
    std::string s = rawoutput.str();
    uint256 outputHash = Hash(MakeUCharSpan(s));
    cout << outputHash.GetHex() << endl;
    cerr << outputHash.GetHex() << endl;
    cout << fmtoutput.str();
}

