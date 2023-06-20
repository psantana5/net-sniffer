#include <iostream>
#include <fstream>
#include <cstring>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// Global variables
std::ofstream logFile;

// Function to handle incoming packets
void packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packetData) {
    // Extract IP header
    struct ip* ipHeader = (struct ip*)(packetData + 14);

    // Extract TCP header
    struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + 14 + ipHeader->ip_hl * 4);

    // Extract UDP header
    struct udphdr* udpHeader = (struct udphdr*)(packetData + 14 + ipHeader->ip_hl * 4);

    // Get source and destination IP addresses
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

    // Get source and destination port numbers
    int srcPort, dstPort;
    if (ipHeader->ip_p == IPPROTO_TCP) {
        srcPort = ntohs(tcpHeader->th_sport);
        dstPort = ntohs(tcpHeader->th_dport);
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        srcPort = ntohs(udpHeader->uh_sport);
        dstPort = ntohs(udpHeader->uh_dport);
    } else {
        return;  // Skip non-TCP/UDP packets
    }

    // Print packet information
    std::cout << "Source IP: " << srcIP << ", Source Port: " << srcPort << std::endl;
    std::cout << "Destination IP: " << dstIP << ", Destination Port: " << dstPort << std::endl;

    // Log packet information to a file
    logFile << "Source IP: " << srcIP << ", Source Port: " << srcPort << std::endl;
    logFile << "Destination IP: " << dstIP << ", Destination Port: " << dstPort << std::endl;

    // Additional analysis or filtering can be performed here
    // ...

    // Feature 1: Packet Length
    std::cout << "Packet Length: " << pkthdr->len << " bytes" << std::endl;
    logFile << "Packet Length: " << pkthdr->len << " bytes" << std::endl;

    // Feature 2: Protocol Type
    std::string protocol = (ipHeader->ip_p == IPPROTO_TCP) ? "TCP" : ((ipHeader->ip_p == IPPROTO_UDP) ? "UDP" : "Other");
    std::cout << "Protocol: " << protocol << std::endl;
    logFile << "Protocol: " << protocol << std::endl;

    // Feature 3: Time of Packet Capture
    std::time_t packetTime = pkthdr->ts.tv_sec;
    std::cout << "Capture Time: " << std::ctime(&packetTime);
    logFile << "Capture Time: " << std::ctime(&packetTime);

    // Feature 4: TTL (Time-to-Live)
    std::cout << "TTL: " << static_cast<int>(ipHeader->ip_ttl) << std::endl;
    logFile << "TTL: " << static_cast<int>(ipHeader->ip_ttl) << std::endl;

    // Feature 5: Flags (TCP)
    if (ipHeader->ip_p == IPPROTO_TCP) {
        std::cout << "TCP Flags: ";
        if (tcpHeader->th_flags & TH_FIN) std::cout << "FIN ";
        if (tcpHeader->th_flags & TH_SYN) std::cout << "SYN ";
        if (tcpHeader->th_flags & TH_RST) std::cout << "RST ";
        if (tcpHeader->th_flags & TH_PUSH) std::cout << "PUSH ";
        if (tcpHeader->th_flags & TH_ACK) std::cout << "ACK ";
        if (tcpHeader->th_flags & TH_URG) std::cout << "URG ";
        std::cout << std::endl;

        logFile << "TCP Flags: ";
        if (tcpHeader->th_flags & TH_FIN) logFile << "FIN ";
        if (tcpHeader->th_flags & TH_SYN) logFile << "SYN ";
        if (tcpHeader->th_flags & TH_RST) logFile << "RST ";
        if (tcpHeader->th_flags & TH_PUSH) logFile << "PUSH ";
        if (tcpHeader->th_flags & TH_ACK) logFile << "ACK ";
        if (tcpHeader->th_flags & TH_URG) logFile << "URG ";
        logFile << std::endl;
    }

    // Feature 6: Payload (First 10 Bytes)
    std::cout << "Payload: ";
    logFile << "Payload: ";
    for (int i = 0; i < 10 && i < pkthdr->len; ++i) {
        std::cout << std::hex << static_cast<int>(packetData[i]) << " ";
        logFile << std::hex << static_cast<int>(packetData[i]) << " ";
    }
    std::cout << std::endl;
    logFile << std::endl;

    // Feature 7: IP Version
    std::cout << "IP Version: " << static_cast<int>(ipHeader->ip_v) << std::endl;
    logFile << "IP Version: " << static_cast<int>(ipHeader->ip_v) << std::endl;

    // Feature 8: Fragment Offset
    std::cout << "Fragment Offset: " << static_cast<int>(ipHeader->ip_off & IP_OFFMASK) << std::endl;
    logFile << "Fragment Offset: " << static_cast<int>(ipHeader->ip_off & IP_OFFMASK) << std::endl;

    // Feature 9: Header Checksum
    std::cout << "Header Checksum: " << static_cast<int>(ipHeader->ip_sum) << std::endl;
    logFile << "Header Checksum: " << static_cast<int>(ipHeader->ip_sum) << std::endl;

    // Feature 10: Total Length
    std::cout << "Total Length: " << ntohs(ipHeader->ip_len) << std::endl;
    logFile << "Total Length: " << ntohs(ipHeader->ip_len) << std::endl;

    // Feature 11: Identification
    std::cout << "Identification: " << ntohs(ipHeader->ip_id) << std::endl;
    logFile << "Identification: " << ntohs(ipHeader->ip_id) << std::endl;

    // Feature 12: Source MAC Address
    std::cout << "Source MAC Address: ";
    for (int i = 6; i < 12; ++i) {
        std::cout << std::hex << static_cast<int>(packetData[i]);
        if (i < 11) std::cout << ":";
    }
    std::cout << std::endl;

    logFile << "Source MAC Address: ";
    for (int i = 6; i < 12; ++i) {
        logFile << std::hex << static_cast<int>(packetData[i]);
        if (i < 11) logFile << ":";
    }
    logFile << std::endl;

    // Feature 13: Destination MAC Address
    std::cout << "Destination MAC Address: ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << static_cast<int>(packetData[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;

    logFile << "Destination MAC Address: ";
    for (int i = 0; i < 6; ++i) {
        logFile << std::hex << static_cast<int>(packetData[i]);
        if (i < 5) logFile << ":";
    }
    logFile << std::endl;

    // Feature 14: IP Header Length
    std::cout << "IP Header Length: " << static_cast<int>(ipHeader->ip_hl * 4) << " bytes" << std::endl;
    logFile << "IP Header Length: " << static_cast<int>(ipHeader->ip_hl * 4) << " bytes" << std::endl;

    // Feature 15: TCP Header Length (if applicable)
    if (ipHeader->ip_p == IPPROTO_TCP) {
        std::cout << "TCP Header Length: " << static_cast<int>(tcpHeader->th_off * 4) << " bytes" << std::endl;
        logFile << "TCP Header Length: " << static_cast<int>(tcpHeader->th_off * 4) << " bytes" << std::endl;
    }

    // Feature 16: UDP Length (if applicable)
    if (ipHeader->ip_p == IPPROTO_UDP) {
        std::cout << "UDP Length: " << ntohs(udpHeader->uh_ulen) << " bytes" << std::endl;
        logFile << "UDP Length: " << ntohs(udpHeader->uh_ulen) << " bytes" << std::endl;
    }

    // Feature 17: IP Header Checksum
    std::cout << "IP Header Checksum: " << static_cast<int>(ipHeader->ip_sum) << std::endl;
    logFile << "IP Header Checksum: " << static_cast<int>(ipHeader->ip_sum) << std::endl;

    // Feature 18: TCP Sequence Number (if applicable)
    if (ipHeader->ip_p == IPPROTO_TCP) {
        std::cout << "TCP Sequence Number: " << ntohl(tcpHeader->th_seq) << std::endl;
        logFile << "TCP Sequence Number: " << ntohl(tcpHeader->th_seq) << std::endl;
    }

    // Feature 19: UDP Checksum (if applicable)
    if (ipHeader->ip_p == IPPROTO_UDP) {
        std::cout << "UDP Checksum: " << static_cast<int>(udpHeader->uh_sum) << std::endl;
        logFile << "UDP Checksum: " << static_cast<int>(udpHeader->uh_sum) << std::endl;
    }

    // Feature 20: Window Size (TCP)
    if (ipHeader->ip_p == IPPROTO_TCP) {
        std::cout << "Window Size: " << ntohs(tcpHeader->th_win) << std::endl;
        logFile << "Window Size: " << ntohs(tcpHeader->th_win) << std::endl;
    }

    std::cout << "------------------------------------------------------" << std::endl;
    logFile << "------------------------------------------------------" << std::endl;
}

// Function to print the main menu
void printMainMenu() {
    std::cout << "---------------------- Main Menu ----------------------" << std::endl;
    std::cout << "1. Start Packet Capture" << std::endl;
    std::cout << "2. Stop Packet Capture" << std::endl;
    std::cout << "3. Exit" << std::endl;
    std::cout << "------------------------------------------------------" << std::endl;
    std::cout << "Please enter your choice: ";
}

// Function to handle main menu input
int handleMainMenuInput() {
    int choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Clear input buffer
    return choice;
}

int main() {
    // Open a network device for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
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

    return 0;
}
