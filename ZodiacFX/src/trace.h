extern bool trace;
#define TRACE(fmt, ...) if (trace) { printf(fmt "\r\n", ## __VA_ARGS__); }
	
// build with this instead, to disable trace for performance.
//#define TRACE(...) ;
