#pragma once
#include <cstdio>
namespace boost{namespace nowide{
  inline FILE* fopen(const char*p,const char*m){return ::fopen(p,m);}
  inline FILE* freopen(const char*p,const char*m,FILE*f){return ::freopen(p,m,f);}
}}
