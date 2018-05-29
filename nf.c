#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>

MODULE_AUTHOR("Christopher Brew");
MODULE_DESCRIPTION("A simple firewall");
MODULE_LICENSE("GPL");

static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

typedef enum
{
    FWR_SADDR,
    FWR_SPORT,
    FWR_DADDR,
    FWR_DPORT,
} fwr_field_t;

struct fw_rule
{
    unsigned int id;
    fwr_field_t field;
    unsigned int value;
    bool allow;
    struct list_head list;
};

static unsigned int fw_rule_id = 0;
static struct fw_rule rules;

void add_rule(fwr_field_t field, unsigned int value, bool allow)
{
    struct fw_rule *new_rule = kmalloc(sizeof(struct fw_rule), GFP_KERNEL);
    new_rule->id = fw_rule_id++;
    new_rule->field = field;
    new_rule->value = value;
    new_rule->allow = allow;

    INIT_LIST_HEAD(&new_rule->list);
    list_add_tail (&new_rule->list, &rules.list);
}

void print_packet(struct sk_buff *skb, bool allowed)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    char sstring[21];
    char dstring[21];
    char *prefix = allowed ? "ALLOWED" : "BLOCKED";

    switch(ip_header->protocol)
    {
        case IPPROTO_TCP:
            tcp_header = tcp_hdr(skb);
            snprintf(sstring, 21, "%pI4:%hu", &ip_header->saddr, ntohs(tcp_header->source));
            snprintf(dstring, 21, "%pI4:%hu", &ip_header->daddr, ntohs(tcp_header->dest));
            printk(KERN_INFO "%s [ TCP  ] %-21s -> %-21s\n", prefix, sstring, dstring);
            break;
        case IPPROTO_UDP:
            udp_header = udp_hdr(skb);
            snprintf(sstring, 21, "%pI4:%hu", &ip_header->saddr, ntohs(udp_header->source));
            snprintf(dstring, 21, "%pI4:%hu", &ip_header->daddr, ntohs(udp_header->dest));
            printk(KERN_INFO "%s [ UDP  ] %-21s -> %-21s\n", prefix, sstring, dstring);
            break;
        case IPPROTO_ICMP:
            snprintf(sstring, 15, "%pI4", &ip_header->saddr);
            snprintf(dstring, 15, "%pI4", &ip_header->daddr);
            printk(KERN_INFO "%s [ ICMP ] %-21s -> %-21s\n", prefix, sstring, dstring);
            break;
        default:
            snprintf(sstring, 15, "%pI4", &ip_header->saddr);
            snprintf(dstring, 15, "%pI4", &ip_header->daddr);
            printk(KERN_INFO "%s [ OTHR ] %-21s -> %-21s\n", prefix, sstring, dstring);
    }
}

unsigned int hook_func(void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state)
{
    unsigned int loopback;
    struct fw_rule *rule;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    __be32 saddr, daddr;
    int sport, dport;

    if(state->hook == NF_INET_LOCAL_IN)
    {
        loopback = state->in->flags & IFF_LOOPBACK;
    }
    else
    {
        loopback = state->out->flags & IFF_LOOPBACK;
    }

    if(!loopback)
    {
        saddr = ntohl(ip_header->saddr);
        daddr = ntohl(ip_header->daddr);
        switch(ip_header->protocol)
        {
            case IPPROTO_TCP:
                tcp_header = tcp_hdr(skb);
                sport = ntohs(tcp_header->source);
                dport = ntohs(tcp_header->dest);
                break;
            case IPPROTO_UDP:
                udp_header = udp_hdr(skb);
                sport = ntohs(udp_header->source);
                dport = ntohs(udp_header->dest);
                break;
            default:
                sport = -1;
                dport = -1;
        }
        list_for_each_entry(rule, &rules.list, list)
        {
            switch(rule->field)
            {
                case FWR_SADDR:
                    if(rule->value == saddr)
                    {
                        print_packet(skb, rule->allow);
                        return rule->allow ? NF_ACCEPT : NF_DROP;
                    }
                    break;
                case FWR_SPORT:
                    if(sport != -1 && rule->value == sport)
                    {
                        print_packet(skb, rule->allow);
                        return rule->allow ? NF_ACCEPT : NF_DROP;
                    }
                    break;
                case FWR_DADDR:
                    if(rule->value == daddr)
                    {
                        print_packet(skb, rule->allow);
                        return rule->allow ? NF_ACCEPT : NF_DROP;
                    }
                    break;
                case FWR_DPORT:
                    if(dport != -1 && rule->value == dport)
                    {
                        print_packet(skb, rule->allow);
                        return rule->allow ? NF_ACCEPT : NF_DROP;
                    }
            }
        }
    }

    return NF_ACCEPT;
}

static int __init hello_init(void)
{
    printk(KERN_INFO "Hello World!\n");

    INIT_LIST_HEAD(&rules.list);

    nfho_in.hook = hook_func;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_in);

    nfho_out.hook = hook_func;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho_out);

    /* Add some sample rules */
    add_rule(FWR_SADDR, 0x805F7801, true);
    add_rule(FWR_SPORT, 80, false);
    add_rule(FWR_DPORT, 80, false);
    /*************************/

    return 0;
}

static void __exit hello_exit(void)
{
    struct fw_rule *rule, *tmp;
    printk(KERN_INFO "Goodbye!\n");

    nf_unregister_net_hook(&init_net, &nfho_in);
    nf_unregister_net_hook(&init_net, &nfho_out);

    list_for_each_entry_safe(rule, tmp, &rules.list, list)
    {
        list_del(&rule->list);
        kfree(rule);
    }
}

module_init(hello_init);
module_exit(hello_exit);
