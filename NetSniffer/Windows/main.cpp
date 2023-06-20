#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pcap.h>

// Log file stream
std::ofstream logFile;

// Function to handle captured packets
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    // Retrieve the timestamp of the packet
    time_t timestamp = pkthdr->ts.tv_sec;
    
    // Parse the Ethernet header
    struct ethhdr* ethernetHeader = (struct ethhdr*)packetData;

    // Extract the source and destination MAC addresses
    std::string sourceMAC = "";
    std::string destMAC = "";
    for (int i = 0; i < ETH_ALEN; i++) {
        sourceMAC += (i == 0 ? "" : ":") + std::to_string(ethernetHeader->h_source[i]);
        destMAC += (i == 0 ? "" : ":") + std::to_string(ethernetHeader->h_dest[i]);
    }

    // Feature 1: MAC Addresses
    std::cout << "Source MAC: " << sourceMAC << std::endl;
    std::cout << "Destination MAC: " << destMAC << std::endl;

    // Parse the IP header
    struct ip* ipHeader = (struct ip*)(packetData + sizeof(struct ethhdr));

    // Feature 2: Source and Destination IP Addresses
    std::string sourceIP = inet_ntoa(ipHeader->ip_src);
    std::string destIP = inet_ntoa(ipHeader->ip_dst);
    std::cout << "Source IP: " << sourceIP << std::endl;
    std::cout << "Destination IP: " << destIP << std::endl;

    // Feature 3: Packet Length
    std::cout << "Packet Length: " << pkthdr->len << " bytes" << std::endl;

    // Feature 4: Protocol
    std::cout << "Protocol: ";
    switch (ipHeader->ip_p) {
        case IPPROTO_TCP:
            std::cout << "TCP" << std::endl;
            break;
        case IPPROTO_UDP:
            std::cout << "UDP" << std::endl;
            break;
        case IPPROTO_ICMP:
            std::cout << "ICMP" << std::endl;
            break;
        default:
            std::cout << "Unknown" << std::endl;
            break;
    }

    // Feature 5: TTL (Time To Live)
    std::cout << "TTL: " << (int)ipHeader->ip_ttl << std::endl;

    // Feature 6: IP Version
    std::cout << "IP Version: ";
    if ((ipHeader->ip_v & 0xF0) == 0x40) {
        std::cout << "IPv4" << std::endl;
    } else if ((ipHeader->ip_v & 0xF0) == 0x60) {
        std::cout << "IPv6" << std::endl;
    } else {
        std::cout << "Unknown" << std::endl;
    }

    // Feature 7: IP Header Length
    std::cout << "IP Header Length: " << (ipHeader->ip_hl * 4) << " bytes" << std::endl;

    // Feature 8: IP Fragmentation
    std::cout << "Fragmentation Flags: ";
    if (ntohs(ipHeader->ip_off) & IP_DF) {
        std::cout << "Don't Fragment (DF)" << std::endl;
    } else if (ntohs(ipHeader->ip_off) & IP_MF) {
        std::cout << "More Fragments (MF)" << std::endl;
    } else {
        std::cout << "No Fragmentation" << std::endl;
    }

    // Feature 9: IP Identification
    std::cout << "Identification: " << ntohs(ipHeader->ip_id) << std::endl;

    // Feature 10: TCP Flags (for TCP packets)
    if (ipHeader->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + sizeof(struct ethhdr) + ipHeader->ip_hl * 4);
        std::cout << "TCP Flags: ";
        if (tcpHeader->syn) {
            std::cout << "SYN ";
        }
        if (tcpHeader->ack) {
            std::cout << "ACK ";
        }
        if (tcpHeader->fin) {
            std::cout << "FIN ";
        }
        if (tcpHeader->rst) {
            std::cout << "RST ";
        }
        if (tcpHeader->psh) {
            std::cout << "PSH ";
        }
        if (tcpHeader->urg) {
            std::cout << "URG ";
        }
        std::cout << std::endl;
    }

    // Feature 11: UDP Length (for UDP packets)
    if (ipHeader->ip_p == IPPROTO_UDP) {
        struct udphdr* udpHeader = (struct udphdr*)(packetData + sizeof(struct ethhdr) + ipHeader->ip_hl * 4);
        std::cout << "UDP Length: " << ntohs(udpHeader->len) << std::endl;
    }

    // Feature 12: ICMP Type and Code (for ICMP packets)
    if (ipHeader->ip_p == IPPROTO_ICMP) {
        struct icmphdr* icmpHeader = (struct icmphdr*)(packetData + sizeof(struct ethhdr) + ipHeader->ip_hl * 4);
        std::cout << "ICMP Type: " << (int)icmpHeader->type << std::endl;
        std::cout << "ICMP Code: " << (int)icmpHeader->code << std::endl;
    }

    // Feature 13: Packet Hex Dump
    std::cout << "Packet Hex Dump:" << std::endl;
    for (int i = 0; i < pkthdr->len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)packetData[i] << " ";
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << std::endl;

    // Feature 14: Log Packet to File
    logFile << "Packet Captured!" << std::endl;
    logFile << "Packet Length: " << pkthdr->len << " bytes" << std::endl;
    logFile << "Timestamp: " << std::ctime(&timestamp);
    logFile << "Source MAC: " << sourceMAC << std::endl;
    logFile << "Destination MAC: " << destMAC << std::endl;
    logFile << "Source IP: " << sourceIP << std::endl;
    logFile << "Destination IP: " << destIP << std::endl;
    logFile << std::endl;
}

// Function to print the main menu
void printMainMenu() {
    std::cout << "Packet Sniffer" << std::endl;
    std::cout << "--------------" << std::endl;
    std::cout << "1. Start Packet Capture" << std::endl;
    std::cout << "2. Stop Packet Capture" << std::endl;
    std::cout << "3. Exit" << std::endl;
    std::cout << "Enter your choice: ";
}

// Function to handle main menu input
int handleMainMenuInput() {
    int choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Clear input buffer
    return choice;
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock" << std::endl;
        return 1;
    }

    // Open a network device for packet capture
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open("YOUR_NET_INTERFACE", 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening network device: " << errbuf << std::endl;
        return 1;
    }

    // Set a packet filter to capture only TCP and UDP packets
    struct bpf_program filter;
    const char* filterExp = "tcp or udp";
    if (pcap_compile(handle, &filter, filterExp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling packet filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Error setting packet filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    // Main menu loop
    bool capturing = false;
    bool exitProgram = false;
    while (!exitProgram) {
        printMainMenu();
        int choice = handleMainMenuInput();

        switch (choice) {
            case 1:
                if (!capturing) {
                    // Open log file for writing captured packets
                    logFile.open("packet_log.txt");
                    if (!logFile.is_open()) {
                        std::cerr << "Error opening log file!" << std::endl;
                        return 1;
                    }

                    // Start capturing packets
                    pcap_loop(handle, 0, packetHandler, nullptr);
                    capturing = true;
                    std::cout << "Packet capturing started." << std::endl;
                } else {
                    std::cout << "Packet capturing is already in progress." << std::endl;
                }
                break;

            case 2:
                if (capturing) {
                    // Stop capturing packets
                    pcap_breakloop(handle);
                    logFile.close();
                    capturing = false;
                    std::cout << "Packet capturing stopped." << std::endl;
                } else {
                    std::cout << "Packet capturing is not in progress." << std::endl;
                }
                break;

            case 3:
                exitProgram = true;
                break;

            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }

    // Close the packet capture handle
    pcap_close(handle);

    // Cleanup Winsock
    WSACleanup();

    return 0;
}
