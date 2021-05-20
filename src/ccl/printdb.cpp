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
        CDBWrapper db(argv[i], 1<<23, false, false);

        CDBIterator* it = db.NewIterator();
        for (it->SeekToFirst(); it->Valid(); it->Next()) {
            std::string strKey, strValue;
            it->GetKey(strKey);
            it->GetValue(strValue);
            rawoutput << strKey << strValue;
            CDataStream ssKey(strKey.data(), strKey.data() + strKey.size(),
                    SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(),
                    SER_DISK, CLIENT_VERSION);
            // Chainstate uses two types of entries:
            // 1) B: hash (hash of the last block in active chain)
            // 2) c<txid>: <ccoins>
            if (strKey == "B") {
                uint256 hashBestChain;
                ssValue >> hashBestChain;
                fmtoutput << "B: " << hashBestChain.GetHex() << endl;
            } else if (strKey.at(0) == 'c') {
                uint256 txhash;
                std::pair<char, uint256> p;
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

                fmtoutput << Hash(strValue.begin(), strValue.end()).GetHex();
                fmtoutput << endl;
            } // blockindex uses five types of entries:
            // 1) b<blockhash>: <cdiskblockindex>
            // 2) f<file number>: <cblockfileinfo>
            // 3) l: <file number> (last file)
            // 4) R: 1 (entry exists when reindexing)
            // 5) F<flag>: {0,1} (setting a bool flag)
            else if (strKey.at(0) == 'b') {
                uint256 blockhash;
                std::pair<char, uint256> p;
                ssKey >> p;
                fmtoutput << p.first << p.second.GetHex();
                CDiskBlockIndex cdbi;
                ssValue >> cdbi;
                fmtoutput << ": " << cdbi.hashPrev.GetHex();
                if (cdbi.GetBlockHash() != p.second)
                    fmtoutput << "," << cdbi.GetBlockHash().GetHex();
                fmtoutput << endl;
            } else if (strKey.at(0) == 'f') {
                std::pair<char, int> p;
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
                char reindex;
                ssValue >> reindex;
                fmtoutput << strKey << ": " << reindex << endl;
            } else if (strKey.at(0) == 'F') {
                std::pair<char, std::string> p;
                ssKey >> p;
                char value;
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
    uint256 outputHash = Hash(s.data(), s.data()+s.size());
    cout << outputHash.GetHex() << endl;
    cerr << outputHash.GetHex() << endl;
    cout << fmtoutput.str();
}
