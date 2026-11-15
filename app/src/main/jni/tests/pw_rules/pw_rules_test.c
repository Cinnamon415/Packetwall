#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "pw_rules.h"
int zdtun_parse_ip(const char *s, zdtun_ip_t *p){ if(strchr(s,'.')) return inet_pton(AF_INET,s,&p->ip4)>0?4:-1; return inet_pton(AF_INET6,s,&p->ip6)>0?6:-1; }
static int fails=0;
static void chk(pw_engine_t *e,int uid,const char*ip,const char*host,int proto,int port,int dns,int exp_match,int exp_block,int exp_ref){
  zdtun_ip_t a={0}; int v=zdtun_parse_ip(ip,&a);
  pw_query_t q={.uid=uid,.ipver=v,.ip=&a,.host=host,.country="",.proto=proto,.port=port,.dns_query=dns};
  pw_verdict_t r=pw_engine_eval(e,&q);
  int ok = r.matched==exp_match && (!exp_match || (r.block==exp_block && r.ref==exp_ref));
  printf("%s uid=%d %s %s -> m=%d b=%d ref=%d\n", ok?"ok  ":"FAIL", uid, ip, host?host:"-", r.matched, r.block, r.ref);
  if(!ok) fails++;
}
int main(int c,char**v){
  char err[100]; pw_engine_t *e=pw_engine_load(v[1],err,100); if(!e){printf("load: %s\n",err);return 1;}
  printf("rules=%d\n", pw_engine_num_rules(e));
  chk(e,1,"8.8.8.8","x.tbank.ru",6,443,0, 1,1,1);       // global block +subs
  chk(e,1,"8.8.8.8","api.tbank.ru",6,443,0, 1,0,2);     // narrower allow wins
  chk(e,1,"8.8.8.8","tbank.ru",6,443,0, 1,1,1);
  chk(e,10100,"8.8.8.8","google.com",6,443,0, 1,1,3);   // app all-block
  chk(e,10100,"8.8.8.8","a.b.allowed.com",6,443,0, 1,0,4); // app exception
  chk(e,10100,"8.8.8.8","allowed.com",6,443,0, 1,1,3);  // ** needs >=1 label
  chk(e,1,"8.8.8.8","evil.com",6,443,0, 1,0,5);         // global allow
  chk(e,10200,"8.8.8.8","evil.com",6,443,0, 1,1,6);     // global allow does not open app block in lower set
  chk(e,1,"1.2.3.4",NULL,6,443,0, 1,1,7);               // cidr+port
  chk(e,1,"1.2.3.4",NULL,6,80,0, 0,0,0);                // port mismatch
  chk(e,10300,"8.8.8.8","a.cdn.net",6,443,0, 1,1,8);    // group rule
  chk(e,10300,"8.8.8.8","a.b.cdn.net",6,443,0, 0,0,0);  // * one label only
  chk(e,1,"8.8.8.8","ads.doubleclick.net",6,443,0, 1,1,-77);
  chk(e,1,"8.8.8.8","good.doubleclick.net",6,443,0, 1,0,-77);
  chk(e,1,"8.8.8.8","sub.exact.tracker.com",6,443,0, 0,0,0);
  chk(e,1,"8.8.8.8","exact.tracker.com",6,443,0, 1,1,-77);
  chk(e,1,"10.1.2.3",NULL,17,53,0, 1,1,-77);
  chk(e,1,"8.8.8.8","ads12.example.org",6,443,0, 1,1,-77);
  chk(e,1051,"10.215.173.2","a.b.allowed.com",17,53,1, 0,0,0); // dns: app allows -> no dns block
  chk(e,1051,"10.215.173.2","x.tbank.ru",17,53,1, 1,1,1);       // dns global block
  chk(e,1051,"10.215.173.2","evil.com",17,53,1, 1,0,5);
  chk(e,1,"9.9.1.1",NULL,6,443,0, 1,1,10);            // ASN prefix blocks
  chk(e,1,"9.9.9.9",NULL,6,443,0, 1,0,11);            // CIDR (narrower) beats ASN
  { zdtun_ip_t a={0}; zdtun_parse_ip("8.8.8.8",&a);
    pw_query_t q={.uid=1,.ipver=4,.ip=&a,.host="x.via.example",.proto=6,.port=443};
    pw_verdict_t v=pw_engine_eval(e,&q); int ok=v.matched && !v.block && v.route==PW_ROUTE_UPSTREAM;
    printf("%s route upstream -> %d\n", ok?"ok  ":"FAIL", v.route); if(!ok) fails++;
    q.host="direct.example"; v=pw_engine_eval(e,&q); ok=v.route==PW_ROUTE_DIRECT;
    printf("%s route direct -> %d\n", ok?"ok  ":"FAIL", v.route); if(!ok) fails++; }
  printf("%s\n", fails?"FAILED":"ALL OK"); pw_engine_destroy(e); return fails;
}
