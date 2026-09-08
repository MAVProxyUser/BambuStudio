#pragma once
#include <iostream>
#include <sstream>
namespace boost{namespace log{}}
struct _NullLog { template<class T> _NullLog& operator<<(const T&){return *this;} };
#define BOOST_LOG_TRIVIAL(x) _NullLog()
