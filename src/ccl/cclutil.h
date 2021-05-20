#ifndef CCLUTIL_H
#define CCLUTIL_H

#include <boost/filesystem.hpp>
#include <string>

bool RotateFile(boost::filesystem::path dir, std::string filename);

#endif
