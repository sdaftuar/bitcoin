#include "cclutil.h"
#include <stdio.h>
#include "util/time.h"

using SystemClock = std::chrono::system_clock;

// Pass in a filename, and if it exists will attempt to rename it
// to filename.N, where N = 1, 2, ..., MAXINT (first value that doesn't
// already exist)

// Returns true if no problems encountered in rotating.
bool RotateFile(std::filesystem::path dir, std::string filename)
{
    std::filesystem::path filepath = dir / filename.c_str();
    if (std::filesystem::exists(filepath)) {
        int appendval = 0;
        char appendbuffer[15];
        while (std::filesystem::exists(filepath)) {
            sprintf(appendbuffer, "%d", appendval);
            std::string tryname = filename + "." + appendbuffer;
            filepath = dir / tryname;
            ++appendval;
        }
        // now move the original filepath to this new one
        std::filesystem::path orig = dir / filename.c_str();
        std::filesystem::rename(orig, filepath);
        if (!std::filesystem::exists(filepath)) {
            return false;
        }
    }
    return true;
}

int64_t GetTimeMicros()
{
    const auto now{SystemClock::now()};
    return int64_t{TicksSinceEpoch<std::chrono::microseconds>(now)};
}
