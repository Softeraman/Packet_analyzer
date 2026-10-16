// Web adapter: uses the project's native PCAP, packet and hostname parsers.
#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
using namespace PacketAnalyzer;
using namespace DPI;
static std::string quote(const std::string& s) {
    std::ostringstream o; o << '"';
    for (unsigned char c:s) {
        if(c=='"'||c=='\\') o << '\\' << c;
        else if(c<32 || c>126) { const char* h="0123456789abcdef"; o << "\\u00" << h[c>>4] << h[c&15]; }
        else o << c;
    }
    o << '"'; return o.str();
}
static std::string lower(std::string s) { for(char& c:s)c=std::tolower(static_cast<unsigned char>(c));return s; }
struct Flow { std::string src,dst,host,app="Unknown",protocol; uint64_t packets=0,bytes=0; bool blocked=false; };
int main(int argc,char** argv) {
    if(argc!=6)return 2;
    std::string blockIP=argv[3],blockApp=lower(argv[4]),blockDomain=lower(argv[5]);
    PcapReader reader;if(!reader.open(argv[1]))return 3;
    if(reader.getGlobalHeader().network!=1)return 4;
    std::map<std::string,Flow> flows; uint64_t total=0,skipped=0,bytes=0;
    RawPacket raw;ParsedPacket p;
    while(reader.readNextPacket(raw)) {
        ++total;bytes+=raw.data.size();
        if(!PacketParser::parse(raw,p)||!p.has_ip||(!p.has_tcp&&!p.has_udp)){++skipped;continue;}
        std::string a=p.src_ip+":"+std::to_string(p.src_port),b=p.dest_ip+":"+std::to_string(p.dest_port);
        std::string key=std::min(a,b)+"|"+std::max(a,b)+"|"+std::to_string(p.protocol);
        auto& f=flows[key];if(!f.packets){f.src=a;f.dst=b;f.protocol=p.has_tcp?"TCP":"UDP";}
        ++f.packets;f.bytes+=raw.data.size();
        if(blockIP==p.src_ip||blockIP==p.dest_ip)f.blocked=true;
        if(f.host.empty()&&p.has_tcp&&p.payload_data&&p.payload_length){
            auto host=SNIExtractor::extract(p.payload_data,p.payload_length);
            if(!host)host=HTTPHostExtractor::extract(p.payload_data,p.payload_length);
            if(host)f.host=*host;
        }
        if(!f.host.empty()) {
            f.app=appTypeToString(sniToAppType(f.host));
            if(f.app=="HTTPS" && (p.src_port==80 || p.dest_port==80))f.app="HTTP";
        }
        if(f.app=="Unknown") {
            if(p.src_port==53||p.dest_port==53)f.app="DNS";
            else if(p.src_port==443||p.dest_port==443)f.app=p.has_udp?"QUIC":"HTTPS";
            else if(p.src_port==80||p.dest_port==80)f.app="HTTP";
        }
    }
    struct Stat {uint64_t packets=0,bytes=0,blocked=0;};
    std::map<std::string,Stat> apps;uint64_t blocked=0;
    std::vector<Flow> sorted;
    for(auto& item:flows){auto& f=item.second;
        f.blocked=f.blocked||(!blockApp.empty()&&lower(f.app)==blockApp)||(!blockDomain.empty()&&lower(f.host).find(blockDomain)!=std::string::npos);
        auto& s=apps[f.app];s.packets+=f.packets;s.bytes+=f.bytes;if(f.blocked){s.blocked+=f.packets;blocked+=f.packets;}sorted.push_back(f);
    }
    std::sort(sorted.begin(),sorted.end(),[](const Flow&a,const Flow&b){return a.bytes>b.bytes;});
    std::ofstream out(argv[2]);
    out << "{\"totalPackets\":"<<total<<",\"totalBytes\":"<<bytes<<",\"skippedPackets\":"<<skipped<<",\"analyzedPackets\":"<<(total-skipped)<<",\"blockedPackets\":"<<blocked<<",\"allowedPackets\":"<<(total-skipped-blocked)<<",\"flowCount\":"<<flows.size()<<",\"applications\":[";
    bool first=true;for(const auto& item:apps){if(!first)out<<',';first=false;out<<"{\"name\":"<<quote(item.first)<<",\"packets\":"<<item.second.packets<<",\"bytes\":"<<item.second.bytes<<",\"blocked\":"<<item.second.blocked<<'}';}
    out<<"],\"flows\":[";first=true;size_t n=0;
    for(const auto& f:sorted){if(n++>=250)break;if(!first)out<<',';first=false;
        out<<"{\"source\":"<<quote(f.src)<<",\"destination\":"<<quote(f.dst)<<",\"hostname\":"<<quote(f.host)<<",\"application\":"<<quote(f.app)<<",\"protocol\":"<<quote(f.protocol)<<",\"packets\":"<<f.packets<<",\"bytes\":"<<f.bytes<<",\"blocked\":"<<(f.blocked?"true":"false")<<'}';}
    out<<"]}";return out.good()?0:5;
}
