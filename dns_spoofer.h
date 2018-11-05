#ifndef DNS_SPOOFER_H
#define DNS_SPOOFER_H

#include <string>
#include <vector>
#include <tins/tins.h>

using namespace Tins;

class DNS_Spoofer
{
    struct Target{
        std::string target;
        std::string redirect;
    };
public:
    DNS_Spoofer();
    void start(std::string interface);
    void add_target(std::string target, std::string redirect);
    void reset();
    void setup(std::string interface);
    bool handle(PDU& pdu);
private:
    PacketSender sender;
    std::vector<Target> targets;
};

#endif // DNS_SPOOFER_H
