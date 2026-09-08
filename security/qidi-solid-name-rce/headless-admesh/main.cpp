#include "stl.h"
#include <cstdio>
#include <string>
static std::string g_sink;
static void progress_cb(int, int, bool&,
    std::string& a, std::string& b, std::string& c, std::string& d, std::string& e){
    // mimic Slic3r::GUI::ProgressDialog::Update using the model-info strings
    g_sink = a + "/" + b + "/" + c + "/" + d + "/" + e;   // derefs each string's data
}
int main(int argc, char **argv){
    if(argc<2){ fprintf(stderr,"usage: %s file.stl\n",argv[0]); return 2; }
    stl_file stl;
    stl_open(&stl, argv[1], progress_cb, 80);
    printf("(parsed without crash)\n");
    return 0;
}
