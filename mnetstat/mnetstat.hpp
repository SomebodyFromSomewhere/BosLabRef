#ifdef MNETSTAT_EXPORT_DLL
#define MNETSTAT_API __declspec(dllexport)
#else
#define MNETSTAT_API __declspec(dllimport)
#endif // MNETSTAT_EXPORT_DLL

namespace mnetstat
{
    extern "C" MNETSTAT_API int tcpV4();
    extern "C" MNETSTAT_API int tcpV6();
    extern "C" MNETSTAT_API void printHeaderV4();
    extern "C" MNETSTAT_API void printHeaderV6();
} // namespace mnetstat