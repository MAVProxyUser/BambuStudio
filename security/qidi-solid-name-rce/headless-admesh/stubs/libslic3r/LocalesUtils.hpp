#pragma once
#include <string>
namespace Slic3r {
class CNumericLocalesSetter { public: CNumericLocalesSetter(){} ~CNumericLocalesSetter(){} };
inline std::string to_string_nozero(double v,int){ return std::to_string(v); }
}
