#include <ccl/cclutil.h>
#include <stdio.h>

// Pass in a filename, and if it exists will attempt to rename it
// to filename.N, where N = 1, 2, ..., MAXINT (first value that doesn't
// already exist)

// Returns true if no problems encountered in rotating.
bool RotateFile(boost::filesystem::path dir, std::string filename)
{
    boost::filesystem::path filepath = dir / filename.c_str();
    if (boost::filesystem::exists(filepath)) {
        int appendval = 0;
        char appendbuffer[15];
        while (boost::filesystem::exists(filepath)) {
            sprintf(appendbuffer, "%d", appendval);
            std::string tryname = filename + "." + appendbuffer;
            filepath = dir / tryname;
            ++appendval;
        }
        // now move the original filepath to this new one
        boost::filesystem::path orig = dir / filename.c_str();
        boost::filesystem::rename(orig, filepath);
        if (!boost::filesystem::exists(filepath)) {
            return false;
        }
    }
    return true;
}
