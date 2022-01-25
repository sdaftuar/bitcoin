#ifndef CCLUTIL_H
#define CCLUTIL_H

#include <filesystem>
#include <string>

bool RotateFile(std::filesystem::path dir, std::string filename);
int64_t GetTimeMicros();

#endif
