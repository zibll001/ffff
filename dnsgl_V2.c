/*
        DNS放大攻击服务器过滤分析工具 - 毕方资源网
        gcc -o dnsgl dnsgl.c -lpthread;chmod 777 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

#define MAX_DOMAIN_LENGTH 256
#define MAX_RESPONSE_SIZE 65535
#define TIMEOUT_SECONDS 3
#define THREAD_COUNT 2000  // 增加到2000线程

typedef struct {
    char domain[MAX_DOMAIN_LENGTH];
    char dns_server[16];
    int request_size;
    int response_size;
    double amplification;
    double response_time;
    int success;
} AmplificationResult;

typedef struct {
    char **dns_servers;
    int server_count;
    char **test_domains;
    int domain_count;
    AmplificationResult *results;
    int *current_index;
    pthread_mutex_t *index_mutex;
    int use_edns;
} ThreadData;

volatile sig_atomic_t stop_flag = 0;

void signal_handler(int sig) {
    stop_flag = 1;
    printf("\n正在停止扫描...\n");
}

// 函数声明
double time_diff(struct timeval *start, struct timeval *end);
int build_dns_query(const char *domain, unsigned char *buffer, int use_edns, int *request_size);
AmplificationResult test_amplification(const char *domain, const char *dns_server, int use_edns);
void *test_thread(void *arg);
char **read_dns_servers_from_file(const char *filename, int *count);
char **generate_test_domains(int *count, char *custom_domain);
int compare_amplification(const void *a, const void *b);
void save_filtered_results(const char *filename, AmplificationResult *results, int count, 
                          double min_amplification, int min_response_size, 
                          int use_amp_filter, int use_size_filter);
void manual_deduplicate(const char *filename);
int compare_strings(const void *a, const void *b);
void free_string_array(char **array, int count);
void print_usage(char *program_name);

// 计算时间差（毫秒）
double time_diff(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 + 
           (end->tv_usec - start->tv_usec) / 1000.0;
}

// 构造DNS查询数据包（支持EDNS扩展）- 优化版本
int build_dns_query(const char *domain, unsigned char *buffer, int use_edns, int *request_size) {
    memset(buffer, 0, 512);
    
    // DNS头
    unsigned short *dns_header = (unsigned short *)buffer;
    dns_header[0] = htons(rand() & 0xFFFF);
    dns_header[1] = htons(0x0100);
    dns_header[2] = htons(1);
    dns_header[3] = 0;
    dns_header[4] = 0;
    dns_header[5] = use_edns ? htons(1) : 0;
    
    // 查询名称 - 优化处理
    unsigned char *qname = buffer + 12;
    const char *p = domain;
    int pos = 0;
    
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (dot - p) : strlen(p);
        
        qname[pos++] = len;
        memcpy(qname + pos, p, len);
        pos += len;
        
        p = dot ? dot + 1 : p + len;
        if (!*p) break;
    }
    qname[pos++] = 0;
    
    // 查询类型和类
    unsigned short *qtype = (unsigned short *)(buffer + 12 + pos);
    *qtype = htons(255);
    pos += 2;
    
    unsigned short *qclass = (unsigned short *)(buffer + 12 + pos);
    *qclass = htons(1);
    pos += 2;
    
    // EDNS扩展
    if (use_edns) {
        unsigned char *edns = buffer + 12 + pos;
        memset(edns, 0, 11);
        edns[0] = 0x00;
        edns[2] = 0x29;
        edns[3] = 0xFF;  // 最大UDP载荷
        edns[4] = 0xFF;
        edns[7] = 0x80;  // DNSSEC OK
        pos += 11;
    }
    
    *request_size = 12 + pos;
    return 12 + pos;
}

// 测试单个域名的放大倍数 - 高性能版本
AmplificationResult test_amplification(const char *domain, const char *dns_server, int use_edns) {
    AmplificationResult result;
    memset(&result, 0, sizeof(result));
    
    strcpy(result.domain, domain);
    strcpy(result.dns_server, dns_server);
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return result;
    }
    
    // 设置超时 - 减少超时时间
    struct timeval timeout = {TIMEOUT_SECONDS, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // 构造DNS查询
    unsigned char query[512];
    int request_size = 0;
    int query_len = build_dns_query(domain, query, use_edns, &request_size);
    
    if (query_len <= 0) {
        close(sockfd);
        return result;
    }
    
    result.request_size = request_size;
    
    // 设置DNS服务器地址
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    
    if (inet_pton(AF_INET, dns_server, &server_addr.sin_addr) != 1) {
        close(sockfd);
        return result;
    }
    
    // 发送查询并计时
    struct timeval start_time, end_time;
    unsigned char response[MAX_RESPONSE_SIZE];
    
    gettimeofday(&start_time, NULL);
    
    ssize_t sent = sendto(sockfd, query, query_len, 0, 
                         (struct sockaddr *)&server_addr, sizeof(server_addr));
    
    if (sent == query_len) {
        ssize_t received = recvfrom(sockfd, response, sizeof(response), 0, NULL, NULL);
        gettimeofday(&end_time, NULL);
        
        if (received > 0) {
            result.response_size = received;
            result.response_time = time_diff(&start_time, &end_time);
            result.amplification = (double)result.response_size / (double)result.request_size;
            result.success = 1;
        }
    }
    
    close(sockfd);
    return result;
}

// 线程函数 - 高性能版本
void *test_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    
    while (!stop_flag) {
        int index;
        
        // 获取下一个要测试的索引 - 无锁操作优化
        pthread_mutex_lock(data->index_mutex);
        if (*data->current_index >= data->server_count * data->domain_count) {
            pthread_mutex_unlock(data->index_mutex);
            break;
        }
        index = (*data->current_index)++;
        pthread_mutex_unlock(data->index_mutex);
        
        // 计算对应的DNS服务器和域名索引
        int server_index = index / data->domain_count;
        int domain_index = index % data->domain_count;
        
        // 测试 - 移除延迟以最大化性能
        AmplificationResult result = test_amplification(
            data->test_domains[domain_index], 
            data->dns_servers[server_index], 
            data->use_edns
        );
        
        data->results[index] = result;
        
        // 移除实时成功结果输出，只通过进度显示
    }
    
    return NULL;
}

// 从文件读取DNS服务器列表
char **read_dns_servers_from_file(const char *filename, int *count) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("无法打开DNS服务器文件");
        return NULL;
    }
    
    char **servers = NULL;
    char line[64];
    int capacity = 10000;  // 增大初始容量
    int size = 0;
    
    servers = malloc(capacity * sizeof(char *));
    if (!servers) {
        fclose(file);
        return NULL;
    }
    
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0;
        
        if (strlen(line) == 0 || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // 快速IP验证
        struct in_addr addr;
        if (inet_pton(AF_INET, line, &addr) != 1) {
            continue;
        }
        
        if (size >= capacity) {
            capacity *= 2;
            char **new_servers = realloc(servers, capacity * sizeof(char *));
            if (!new_servers) {
                for (int i = 0; i < size; i++) free(servers[i]);
                free(servers);
                fclose(file);
                return NULL;
            }
            servers = new_servers;
        }
        
        servers[size] = malloc(strlen(line) + 1);
        if (!servers[size]) {
            for (int i = 0; i < size; i++) free(servers[i]);
            free(servers);
            fclose(file);
            return NULL;
        }
        strcpy(servers[size], line);
        size++;
    }
    
    fclose(file);
    *count = size;
    return servers;
}

// 生成测试域名列表 - 优化版本
char **generate_test_domains(int *count, char *custom_domain) {
    char **domain_list;
    int domain_count;
    
    // 如果提供了自定义域名，则使用自定义域名
    if (custom_domain != NULL && strlen(custom_domain) > 0) {
        domain_count = 1;
        domain_list = malloc(domain_count * sizeof(char *));
        domain_list[0] = malloc(strlen(custom_domain) + 1);
        strcpy(domain_list[0], custom_domain);
    } else {
        // 否则使用默认域名列表
        char *domains[] = {
            "dad.de"
        };
        
        domain_count = sizeof(domains) / sizeof(domains[0]);
        domain_list = malloc(domain_count * sizeof(char *));
        
        for (int i = 0; i < domain_count; i++) {
            domain_list[i] = malloc(strlen(domains[i]) + 1);
            strcpy(domain_list[i], domains[i]);
        }
    }
    
    *count = domain_count;
    return domain_list;
}

// 字符串比较函数
int compare_strings(const void *a, const void *b) {
    const char *str1 = *(const char **)a;
    const char *str2 = *(const char **)b;
    return strcmp(str1, str2);
}

// 手动去重备用方案
void manual_deduplicate(const char *filename) {
    printf("[DEBUG] 开始手动去重: %s\n", filename);
    fflush(stdout);
    
    FILE *file = fopen(filename, "r");
    if (!file) return;
    
    // 读取所有IP
    char **ips = NULL;
    char line[64];
    int capacity = 10000;
    int count = 0;
    
    ips = malloc(capacity * sizeof(char *));
    
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0;
        
        if (count >= capacity) {
            capacity *= 2;
            char **new_ips = realloc(ips, capacity * sizeof(char *));
            if (!new_ips) break;
            ips = new_ips;
        }
        
        ips[count] = malloc(strlen(line) + 1);
        strcpy(ips[count], line);
        count++;
    }
    fclose(file);
    
    printf("[DEBUG] 读取了 %d 行数据\n", count);
    fflush(stdout);
    
    if (count == 0) {
        free(ips);
        return;
    }
    
    // 排序
    printf("[DEBUG] 开始排序...\n");
    fflush(stdout);
    qsort(ips, count, sizeof(char *), compare_strings);
    printf("[DEBUG] 排序完成\n");
    fflush(stdout);
    
    // 去重并写回文件
    file = fopen(filename, "w");
    if (!file) {
        for (int i = 0; i < count; i++) free(ips[i]);
        free(ips);
        return;
    }
    
    int unique_count = 0;
    const char *last_ip = "";
    
    for (int i = 0; i < count; i++) {
        if (i == 0 || strcmp(ips[i], last_ip) != 0) {
            fprintf(file, "%s\n", ips[i]);
            last_ip = ips[i];
            unique_count++;
        }
        free(ips[i]);
        
        // 进度显示
        if (i % 10000 == 0) {
            printf("[DEBUG] 手动去重进度: %d/%d\n", i, count);
            fflush(stdout);
        }
    }
    
    free(ips);
    fclose(file);
    
    printf("手动去重完成，共 %d 个唯一IP\n", unique_count);
    fflush(stdout);
}

// 保存过滤结果到文件 - 优化版本：使用系统命令去重
void save_filtered_results(const char *filename, AmplificationResult *results, int count, 
                          double min_amplification, int min_response_size, 
                          int use_amp_filter, int use_size_filter) {
    printf("[DEBUG] 开始保存过滤结果到: %s\n", filename);
    printf("[DEBUG] 总记录数: %d\n", count);
    fflush(stdout);
    
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("错误: 无法创建输出文件: %s\n", filename);
        return;
    }
    
    int saved_count = 0;
    
    printf("[DEBUG] 开始第一遍过滤写入...\n");
    fflush(stdout);
    
    // 第一遍：快速写入所有符合条件的IP（可能有重复）
    for (int i = 0; i < count; i++) {
        if (results[i].success) {
            int meets_amp_criteria = !use_amp_filter || results[i].amplification >= min_amplification;
            int meets_size_criteria = !use_size_filter || results[i].response_size >= min_response_size;
            
            if (meets_amp_criteria && meets_size_criteria) {
                fprintf(file, "%s\n", results[i].dns_server);
                saved_count++;
            }
        }
        
        // 进度显示
        if (i % 100000 == 0) {
            printf("保存进度: %d/%d (%.1f%%)\n", i, count, (double)i/count*100);
            fflush(stdout);
        }
    }
    
    fclose(file);
    printf("[DEBUG] 初步保存完成，共 %d 个IP（包含重复）\n", saved_count);
    fflush(stdout);
    
    // 使用系统命令去重
    printf("[DEBUG] 开始系统去重...\n");
    fflush(stdout);
    char command[512];
    snprintf(command, sizeof(command), "sort -u %s -o %s.tmp && mv %s.tmp %s", 
             filename, filename, filename, filename);
    
    int ret = system(command);
    if (ret != 0) {
        printf("警告: 去重命令执行失败，使用手动去重\n");
        fflush(stdout);
        // 手动去重备用方案
        manual_deduplicate(filename);
    } else {
        printf("[DEBUG] 系统去重完成\n");
        fflush(stdout);
    }
    
    // 重新计数唯一IP数量
    printf("[DEBUG] 开始计数唯一IP...\n");
    fflush(stdout);
    FILE *count_file = fopen(filename, "r");
    int unique_count = 0;
    char line[64];
    while (fgets(line, sizeof(line), count_file)) {
        unique_count++;
        
        // 进度显示（每10000行显示一次）
        if (unique_count % 10000 == 0) {
            printf("[DEBUG] 已计数 %d 个唯一IP...\n", unique_count);
            fflush(stdout);
        }
    }
    fclose(count_file);
    
    printf("[DEBUG] 最终计数完成\n");
    fflush(stdout);
    
    // 根据使用的过滤器显示不同的消息
    if (use_amp_filter && use_size_filter) {
        printf("保存了 %d 个唯一的同时满足放大倍数>=%.1fx和响应大小>=%d字节的DNS服务器IP到: %s\n", 
               unique_count, min_amplification, min_response_size, filename);
    } else if (use_amp_filter) {
        printf("保存了 %d 个唯一的放大倍数>=%.1fx的DNS服务器IP到: %s\n", 
               unique_count, min_amplification, filename);
    } else if (use_size_filter) {
        printf("保存了 %d 个唯一的响应大小>=%d字节的DNS服务器IP到: %s\n", 
               unique_count, min_response_size, filename);
    } else {
        printf("保存了 %d 个唯一的DNS服务器IP到: %s\n", unique_count, filename);
    }
    fflush(stdout);
}

// 比较函数，用于按放大倍数排序
int compare_amplification(const void *a, const void *b) {
    const AmplificationResult *ra = (const AmplificationResult *)a;
    const AmplificationResult *rb = (const AmplificationResult *)b;
    
    if (ra->success != rb->success) {
        return rb->success - ra->success;
    }
    
    if (rb->amplification != ra->amplification) {
        return (rb->amplification > ra->amplification) ? 1 : -1;
    }
    
    return rb->response_size - ra->response_size;
}

// 释放数组内存
void free_string_array(char **array, int count) {
    if (!array) return;
    
    for (int i = 0; i < count; i++) {
        if (array[i]) free(array[i]);
    }
    free(array);
}

void print_usage(char *program_name) {
    printf("DNS放大攻击服务器过滤分析工具 - 毕方资源网\n");
    printf("================================================\n\n");
    printf("用法: %s [-f 输入文件] [-o 输出文件] [-min-amp 倍数] [-min-size 大小] [-yu 域名]\n\n", program_name);
    printf("参数说明:\n");
    printf("  -f <文件>        输入文件，包含DNS服务器IP列表 (默认: dns_servers.txt)\n");
    printf("  -o <文件>        输出文件，保存过滤结果 (默认: high_amplification.txt)\n");
    printf("  -min-amp <倍数>  最小放大倍数，只保存大于等于此倍数的结果\n");
    printf("  -min-size <大小> 最小响应大小(字节)，只保存大于等于此大小的结果\n");
    printf("  -yu <域名>       自定义测试域名 (例如: -yu www.bfbke.com)\n");
    printf("  -h               显示此帮助信息\n\n");
    printf("示例:\n");
    printf("  %s -f dns.txt -o result.txt -min-amp 50\n", program_name);
    printf("  %s -f dns.txt -o result.txt -min-size 4000\n", program_name);
    printf("  %s -f dns.txt -o result.txt -min-amp 50 -min-size 4000\n", program_name);
    printf("  %s -f dns.txt -yu www.bfbke.com -min-amp 30\n", program_name);
}

int main(int argc, char *argv[]) {
    // 如果没有参数，显示帮助信息
    if (argc == 1) {
        print_usage(argv[0]);
        return 0;
    }
    
    printf("DNS放大攻击服务器过滤分析工具 - 毕方资源网\n");
    printf("================================================\n\n");
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    
    char *input_file = "dnsamp.txt";
    char *output_file = "dns.txt";
    int use_edns = 1;  // 默认启用EDNS
    double min_amplification = 0;  // 默认不限制放大倍数
    int min_response_size = 0;     // 默认不限制响应大小
    int use_amp_filter = 0;        // 是否使用放大倍数过滤
    int use_size_filter = 0;       // 是否使用响应大小过滤
    char *custom_domain = NULL;    // 自定义测试域名
    
    // 快速解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) input_file = argv[++i];
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) output_file = argv[++i];
        else if (strcmp(argv[i], "-min-amp") == 0 && i + 1 < argc) {
            min_amplification = atof(argv[++i]);
            use_amp_filter = 1;
        }
        else if (strcmp(argv[i], "-min-size") == 0 && i + 1 < argc) {
            min_response_size = atoi(argv[++i]);
            use_size_filter = 1;
        }
        else if (strcmp(argv[i], "-yu") == 0 && i + 1 < argc) {
            custom_domain = argv[++i];
        }
        else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else {
            printf("错误: 未知参数 '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // 读取DNS服务器列表
    printf("[DEBUG] 开始读取DNS服务器列表...\n");
    fflush(stdout);
    int server_count = 0;
    char **dns_servers = read_dns_servers_from_file(input_file, &server_count);
    
    if (!dns_servers || server_count == 0) {
        printf("错误: 无法读取DNS服务器列表: %s\n", input_file);
        return 1;
    }
    printf("[DEBUG] DNS服务器列表读取完成: %d 个服务器\n", server_count);
    fflush(stdout);
    
    // 生成测试域名列表
    printf("[DEBUG] 开始生成测试域名列表...\n");
    fflush(stdout);
    int domain_count = 0;
    char **test_domains = generate_test_domains(&domain_count, custom_domain);
    
    if (!test_domains || domain_count == 0) {
        printf("错误: 无法生成测试域名列表\n");
        free_string_array(dns_servers, server_count);
        return 1;
    }
    printf("[DEBUG] 测试域名列表生成完成: %d 个域名\n", domain_count);
    fflush(stdout);
    
    printf("输入文件: %s\n", input_file);
    printf("DNS服务器数量: %d\n", server_count);
    
    // 显示使用的域名
    if (custom_domain != NULL) {
        printf("测试域名: %s (自定义)\n", custom_domain);
    } else {
        printf("测试域名数量: %d\n", domain_count);
    }
    
    printf("使用EDNS扩展: 是\n");
    
    // 根据使用的过滤器显示相应的条件
    if (use_amp_filter && use_size_filter) {
        printf("过滤条件: 放大倍数>=%.1fx AND 响应大小>=%d字节\n", min_amplification, min_response_size);
    } else if (use_amp_filter) {
        printf("过滤条件: 放大倍数>=%.1fx\n", min_amplification);
    } else if (use_size_filter) {
        printf("过滤条件: 响应大小>=%d字节\n", min_response_size);
    } else {
        printf("过滤条件: 无 (保存所有成功的响应)\n");
    }
    
    printf("总测试数量: %d\n", server_count * domain_count);
    printf("线程数: %d\n", THREAD_COUNT);
    printf("按 Ctrl+C 停止测试\n\n");
    fflush(stdout);
    
    // 初始化结果数组
    printf("[DEBUG] 开始分配结果数组内存...\n");
    fflush(stdout);
    int total_tests = server_count * domain_count;
    AmplificationResult *results = calloc(total_tests, sizeof(AmplificationResult));
    if (!results) {
        printf("错误: 内存分配失败\n");
        free_string_array(dns_servers, server_count);
        free_string_array(test_domains, domain_count);
        return 1;
    }
    printf("[DEBUG] 结果数组内存分配完成: %d 条记录\n", total_tests);
    fflush(stdout);
    
    // 初始化多线程相关
    int current_index = 0;
    pthread_mutex_t index_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t threads[THREAD_COUNT];
    ThreadData thread_data[THREAD_COUNT];
    
    printf("启动 %d 个线程...\n", THREAD_COUNT);
    fflush(stdout);
    
    // 创建线程
    for (int i = 0; i < THREAD_COUNT; i++) {
        thread_data[i].dns_servers = dns_servers;
        thread_data[i].server_count = server_count;
        thread_data[i].test_domains = test_domains;
        thread_data[i].domain_count = domain_count;
        thread_data[i].results = results;
        thread_data[i].current_index = &current_index;
        thread_data[i].index_mutex = &index_mutex;
        thread_data[i].use_edns = use_edns;
        
        if (pthread_create(&threads[i], NULL, test_thread, &thread_data[i]) != 0) {
            printf("警告: 无法创建线程 %d\n", i);
            fflush(stdout);
        }
    }
    
    // 显示进度
    int last_progress = -1;
    int last_current_index = 0;
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    
    while (!stop_flag && current_index < total_tests) {
        int progress = (current_index * 100) / total_tests;
        if (progress != last_progress || current_index != last_current_index) {
            gettimeofday(&current_time, NULL);
            double elapsed = time_diff(&start_time, &current_time) / 1000.0; // 转换为秒
            
            // 计算速度（测试/秒）
            double tests_per_second = current_index / elapsed;
            
            // 计算剩余时间
            int remaining_tests = total_tests - current_index;
            double remaining_time = remaining_tests / tests_per_second;
            
            printf("进度: %d%% (%d/%d) | 速度: %.1f 测试/秒 | 剩余时间: %.1f 秒\r", 
                   progress, current_index, total_tests, 
                   tests_per_second, remaining_time);
            fflush(stdout);
            
            last_progress = progress;
            last_current_index = current_index;
        }
        usleep(200000);  // 200ms检查一次进度
    }
    
    // 等待所有线程完成
    printf("\n[DEBUG] 等待所有线程完成...\n");
    fflush(stdout);
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (threads[i]) pthread_join(threads[i], NULL);
    }
    
    pthread_mutex_destroy(&index_mutex);
    
    if (stop_flag) {
        printf("\n测试被用户中断\n");
    } else {
        printf("\n测试完成! 处理了 %d 个测试\n", current_index);
    }
    fflush(stdout);
    
    // 快速统计
    printf("[DEBUG] 开始快速统计...\n");
    fflush(stdout);
    int valid_count = 0;
    int filtered_count = 0;
    
    for (int i = 0; i < total_tests; i++) {
        if (results[i].success) {
            valid_count++;
            
            int meets_amp_criteria = 1;
            int meets_size_criteria = 1;
            
            // 检查放大倍数条件
            if (use_amp_filter && results[i].amplification < min_amplification) {
                meets_amp_criteria = 0;
            }
            
            // 检查响应大小条件
            if (use_size_filter && results[i].response_size < min_response_size) {
                meets_size_criteria = 0;
            }
            
            // 根据使用的过滤器统计符合条件的数量
            if ((!use_amp_filter && !use_size_filter) || // 没有指定过滤器，统计所有成功的
                (use_amp_filter && !use_size_filter && meets_amp_criteria) || // 只使用放大倍数过滤
                (!use_amp_filter && use_size_filter && meets_size_criteria) || // 只使用响应大小过滤
                (use_amp_filter && use_size_filter && meets_amp_criteria && meets_size_criteria)) { // 同时使用两个过滤器
                filtered_count++;
            }
        }
    }
    
    printf("[DEBUG] 统计完成\n");
    fflush(stdout);
    
    printf("\n统计信息:\n");
    printf("总测试数: %d\n", total_tests);
    printf("有效响应: %d (%.1f%%)\n", valid_count, (double)valid_count / total_tests * 100);
    
    // 根据使用的过滤器显示不同的统计信息
    if (use_amp_filter && use_size_filter) {
        printf("同时满足放大倍数>=%.1fx和响应大小>=%d字节的组合: %d (%.1f%%)\n", 
               min_amplification, min_response_size, filtered_count, (double)filtered_count / total_tests * 100);
    } else if (use_amp_filter) {
        printf("放大倍数>=%.1fx的组合: %d (%.1f%%)\n", 
               min_amplification, filtered_count, (double)filtered_count / total_tests * 100);
    } else if (use_size_filter) {
        printf("响应大小>=%d字节的组合: %d (%.1f%%)\n", 
               min_response_size, filtered_count, (double)filtered_count / total_tests * 100);
    } else {
        printf("成功组合: %d (%.1f%%)\n", filtered_count, (double)filtered_count / total_tests * 100);
    }
    fflush(stdout);
    
    // 按放大倍数排序
    printf("[DEBUG] 开始排序结果...\n");
    fflush(stdout);
    qsort(results, total_tests, sizeof(AmplificationResult), compare_amplification);
    printf("[DEBUG] 排序完成\n");
    fflush(stdout);
    
    // 显示前10个最佳结果
    printf("\n前10个最佳放大组合:\n");
    printf("%-15s %-20s %-6s %-6s %-8s %-8s\n", 
           "DNS服务器", "域名", "请求", "响应", "倍数", "时间");
    printf("------------------------------------------------------------\n");
    fflush(stdout);
    
    int display_count = (filtered_count < 10) ? filtered_count : 10;
    int displayed = 0;
    for (int i = 0; i < total_tests && displayed < display_count; i++) {
        if (results[i].success) {
            int meets_amp_criteria = 1;
            int meets_size_criteria = 1;
            
            // 检查放大倍数条件
            if (use_amp_filter && results[i].amplification < min_amplification) {
                meets_amp_criteria = 0;
            }
            
            // 检查响应大小条件
            if (use_size_filter && results[i].response_size < min_response_size) {
                meets_size_criteria = 0;
            }
            
            // 根据使用的过滤器决定是否显示
            if ((!use_amp_filter && !use_size_filter) || // 没有指定过滤器，显示所有成功的
                (use_amp_filter && !use_size_filter && meets_amp_criteria) || // 只使用放大倍数过滤
                (!use_amp_filter && use_size_filter && meets_size_criteria) || // 只使用响应大小过滤
                (use_amp_filter && use_size_filter && meets_amp_criteria && meets_size_criteria)) { // 同时使用两个过滤器
                
                printf("%-15s %-20s %-6d %-6d %-8.1f %-8.1f\n",
                       results[i].dns_server,
                       results[i].domain,
                       results[i].request_size,
                       results[i].response_size,
                       results[i].amplification,
                       results[i].response_time);
                displayed++;
            }
        }
    }
    printf("[DEBUG] 前10结果显示完成\n");
    fflush(stdout);
    
    // 保存过滤结果
    printf("[DEBUG] 开始保存过滤结果...\n");
    fflush(stdout);
    save_filtered_results(output_file, results, total_tests, min_amplification, min_response_size, use_amp_filter, use_size_filter);
    printf("[DEBUG] 保存过滤结果完成\n");
    fflush(stdout);
    
    // 清理内存
    printf("[DEBUG] 开始清理内存...\n");
    fflush(stdout);
    free_string_array(dns_servers, server_count);
    free_string_array(test_domains, domain_count);
    free(results);
    printf("[DEBUG] 内存清理完成，程序结束\n");
    fflush(stdout);
    
    return 0;
}