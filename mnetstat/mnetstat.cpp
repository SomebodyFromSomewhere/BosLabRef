#include "mnetstat.hpp"

#include <iostream>
#include <string>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <conio.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <ip2string.h>

// Need to link with Iphlpapi.lib and Ws2_32.lib.
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

std::string ipV4AddressToString(unsigned long address)
{
    in_addr ipAddr;
    std::string sAddr;

    ipAddr.S_un.S_addr = address;

    sAddr = std::string(inet_ntoa(ipAddr));

    return sAddr;
}

std::string ipV6AddressToString(IN6_ADDR address)
{
    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(23, &address, (PSTR)ipstr, sizeof(ipstr));

    return std::string(ipstr);
}

bool cmpTcpRow(const MIB_TCPROW2 &left, const MIB_TCPROW2 &right)
{
    if (left.dwLocalAddr != right.dwLocalAddr)
        return false;
    if (left.dwLocalPort != right.dwLocalPort)
        return false;
    if (left.dwRemoteAddr != right.dwRemoteAddr)
        return false;
    if (left.dwRemotePort != right.dwRemotePort)
        return false;
    if (left.dwOwningPid != right.dwOwningPid)
        return false;
    if (left.dwOffloadState != right.dwOffloadState)
        return false;
    return true;
}

bool cmpInAddr(IN6_ADDR left, IN6_ADDR right)
{
    for (size_t i = 0; i < 8; i++)
    {
        if (left.u.Word[i] != right.u.Word[i])
            return false;
    }

    return true;
}

bool cmpTcpRow(const MIB_TCP6ROW2 &left, const MIB_TCP6ROW2 &right)
{
    if (!cmpInAddr(left.LocalAddr, right.LocalAddr))
        return false;
    if (left.dwLocalScopeId != right.dwLocalScopeId)
        return false;
    if (left.dwLocalPort != right.dwLocalPort)
        return false;
    if (!cmpInAddr(left.RemoteAddr, right.RemoteAddr))
        return false;
    if (left.dwRemoteScopeId != right.dwRemoteScopeId)
        return false;
    if (left.dwRemotePort != right.dwRemotePort)
        return false;
    if (left.dwOwningPid != right.dwOwningPid)
        return false;
    if (left.dwOffloadState != right.dwOffloadState)
        return false;
    return true;
}

std::string tcpStateToString(unsigned long state)
{
    switch (state)
    {
    case MIB_TCP_STATE_CLOSED:
        return "CLOSED";
        break;
    case MIB_TCP_STATE_LISTEN:
        return "LISTEN";
        break;
    case MIB_TCP_STATE_SYN_SENT:
        return "SYN-SENT";
        break;
    case MIB_TCP_STATE_SYN_RCVD:
        return "SYN-RECEIVED";
        break;
    case MIB_TCP_STATE_ESTAB:
        return "ESTABLISHED";
        break;
    case MIB_TCP_STATE_FIN_WAIT1:
        return "FIN-WAIT-1";
        break;
    case MIB_TCP_STATE_FIN_WAIT2:
        return "FIN-WAIT-2 ";
        break;
    case MIB_TCP_STATE_CLOSE_WAIT:
        return "CLOSE-WAIT";
        break;
    case MIB_TCP_STATE_CLOSING:
        return "CLOSING";
        break;
    case MIB_TCP_STATE_LAST_ACK:
        return "LAST-ACK";
        break;
    case MIB_TCP_STATE_TIME_WAIT:
        return "TIME-WAIT";
        break;
    case MIB_TCP_STATE_DELETE_TCB:
        return "DELETE-TCB";
        break;
    default:
        return "UNKNOWN dwState value: " + std::to_string(state);
        break;
    }
}

void printTcpRow(const MIB_TCPROW2 &row)
{
    std::cout << "\tTCP\t" << std::setw(22) << ipV4AddressToString(row.dwLocalAddr) + ":" + std::to_string(row.dwLocalPort) << "\t\t"
              << std::setw(22) << ipV4AddressToString(row.dwRemoteAddr) + ":" + std::to_string(row.dwRemotePort) << "\t\t" << tcpStateToString(row.dwState) << std::endl;
}

void printTcpRow(const MIB_TCP6ROW2 &row)
{
    std::cout << "\tTCP\t" << std::setw(50) << ipV6AddressToString(row.LocalAddr) + ":" + std::to_string(row.dwLocalPort) << "\t\t"
              << std::setw(50) << ipV6AddressToString(row.RemoteAddr) + ":" + std::to_string(row.dwRemotePort) << "\t\t" << tcpStateToString(row.State) << std::endl;
}

int mnetstat::tcpV4()
{
    std::vector<MIB_TCPROW2> records = {};

    PMIB_TCPTABLE2 pTcpTable;
    unsigned long ulSize = 0;
    unsigned long ulRetVal = 0;

    pTcpTable = (MIB_TCPTABLE2 *)malloc(sizeof(MIB_TCPTABLE2));

    if (pTcpTable == NULL)
    {
        std::cerr << "[ERR][TCP4]Unable to allocate memmory for tcp table." << std::endl;
        return -1;
    }

    ulSize = sizeof(MIB_TCPTABLE2);
    char c;
    bool shouldClose = false;
    std::cout << std::left;
    while (!shouldClose)
    {
        // Retriving size of table.
        if ((ulRetVal = GetTcpTable2(pTcpTable, &ulSize, true)) == ERROR_INSUFFICIENT_BUFFER)
        {
            free(pTcpTable);
            pTcpTable = (MIB_TCPTABLE2 *)malloc(ulSize);
            if (pTcpTable == NULL)
            {
                std::cerr << "[ERR][TCP4]Unable to allocate memmory for tcp table." << std::endl;
                std::cout << std::right;
                return -1;
            }
            continue;
        }

        // Second call to retrive actual data.
        if (ulRetVal == NO_ERROR)
        {
            for (size_t i = 0; i < pTcpTable->dwNumEntries; i++)
            {
                bool exists = false;
                for (auto &&r : records)
                {
                    if (cmpTcpRow(pTcpTable->table[i], r))
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    printTcpRow(pTcpTable->table[i]);
                    records.push_back(pTcpTable->table[i]);
                }
            }
            Sleep(100);
        }
        else
        {
            free(pTcpTable);
            std::cout << std::right;
            std::cerr << "[ERR][TCP4]GetTcpTable2 failed with " << ulRetVal << " error code." << std::endl;
            return -1;
        }
        c = getch();
        if (c == 27)
            shouldClose = true;
    }
    std::cout << std::right;

    free(pTcpTable);

    return 0;
}

int mnetstat::tcpV6()
{
    std::vector<MIB_TCP6ROW2> records = {};

    PMIB_TCP6TABLE2 pTcpTable;
    unsigned long ulSize = 0;
    unsigned long ulRetVal = 0;

    pTcpTable = (MIB_TCP6TABLE2 *)malloc(sizeof(MIB_TCP6TABLE2));

    if (pTcpTable == NULL)
    {
        std::cerr << "[ERR][TCP6]Unable to allocate memmory for tcp table." << std::endl;
        return -1;
    }

    ulSize = sizeof(MIB_TCP6TABLE2);
    bool shouldClose = false;
    char c;
    std::cout << std::left;
    while (!shouldClose)
    {
        // Retriving size of table.
        if ((ulRetVal = GetTcp6Table2(pTcpTable, &ulSize, true)) == ERROR_INSUFFICIENT_BUFFER)
        {
            free(pTcpTable);
            pTcpTable = (MIB_TCP6TABLE2 *)malloc(ulSize);
            if (pTcpTable == NULL)
            {
                std::cerr << "[ERR][TCP6]Unable to allocate memmory for tcp table." << std::endl;
                std::cout << std::right;
                return -1;
            }
            continue;
        }

        // Second call to retrive actual data.
        if (ulRetVal == NO_ERROR)
        {
            for (size_t i = 0; i < pTcpTable->dwNumEntries; i++)
            {
                bool exists = false;
                for (auto &&r : records)
                {
                    if (cmpTcpRow(pTcpTable->table[i], r))
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                {
                    printTcpRow(pTcpTable->table[i]);
                    records.push_back(pTcpTable->table[i]);
                }
            }
            Sleep(100);
        }
        else
        {
            free(pTcpTable);
            std::cout << std::right;
            std::cerr << "[ERR][TCP6]GetTcpTable2 failed with " << ulRetVal << " error code." << std::endl;
            return -1;
        }
        c = getch();
        if (c == 27)
            shouldClose = true;
    }
    std::cout << std::right;

    free(pTcpTable);

    return 0;
}

void mnetstat::printHeaderV4()
{
    std::cout << std::left;
    std::cout << "\tPROTO\t" << std::setw(19) << "Local Address"
              << "\t\t"
              << std::setw(22) << "Foreign Address"
              << "\t\t"
              << "State" << std::endl;
    std::cout << std::right;
}

void mnetstat::printHeaderV6()
{
    std::cout << std::left;
    std::cout << "\tPROTO\t" << std::setw(47) << "Local Address"
              << "\t\t"
              << std::setw(50) << "Foreign Address"
              << "\t\t"
              << "State" << std::endl;
    std::cout << std::right;
}
