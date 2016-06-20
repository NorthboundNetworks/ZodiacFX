extern bool trace;
#define TRACE(...) if (trace) { printf(__VA_ARGS__); }
// build with this instead, to disable trace for performance.
// #define TRACE(...) ;
