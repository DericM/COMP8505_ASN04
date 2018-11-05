#ifndef ARP_SPOOFER_H
#define ARP_SPOOFER_H

#include <string>
#include <tins/tins.h>

using namespace Tins;

class ARP_Spoofer
{
public:
    ARP_Spoofer();
    void add_victim(std::string router, std::string victim);
    void reset();
    int setup(std::string router, std::string victim);
    void do_arp_spoofing(NetworkInterface iface,
                         IPv4Address gw,
                         IPv4Address victim,
                         const NetworkInterface::Info& info);

private:
    bool running;

};

#endif // ARP_SPOOFER_H
