#include <iostream>
#include <string>
#include "mnetstat.hpp"

int main(int argc, char **argv)
{
    for (size_t i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "/6") == 0)
        {
            mnetstat::printHeaderV6();
            mnetstat::tcpV6();
            break;
        }
    }
    mnetstat::printHeaderV4();
    mnetstat::tcpV4();
    return 0;
}