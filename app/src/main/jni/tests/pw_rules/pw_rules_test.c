#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
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
  // suffix index: "**.x" = one or more labels, "*.x"+subdomains likewise; trailing dot ignored
  chk(e,1,"8.8.8.8","a.b.deep.example",6,443,0, 1,1,30);
  chk(e,1,"8.8.8.8","deep.example",6,443,0, 0,0,0);
  chk(e,1,"8.8.8.8","x.y.one.example",6,443,0, 1,1,31);
  chk(e,1,"8.8.8.8","one.example",6,443,0, 0,0,0);
  chk(e,1,"8.8.8.8","x.tbank.ru.",6,443,0, 1,1,1);
  chk(e,1,"8.8.8.8","X.TBANK.RU",6,443,0, 1,1,1);
  // IP index: narrower prefix wins, exact host address, v4 and v6
  chk(e,1,"2001:db8:5::1",NULL,6,443,0, 1,1,32);
  chk(e,1,"2001:db8:1::1",NULL,6,443,0, 1,0,33);
  chk(e,1,"203.0.113.7",NULL,6,443,0, 1,1,34);
  chk(e,1,"203.0.113.8",NULL,6,443,0, 0,0,0);

  // glob matcher: the audit's "**" bomb must finish at once
  { char pat[200]=""; for(int i=0;i<14;i++) strcat(pat,"**."); strcat(pat,"zz");
    char host[120]=""; for(int i=0;i<38;i++) strcat(host,"a."); strcat(host,"com");
    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    bool m=pw_match_domain(pat,host,true);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double ms=(t1.tv_sec-t0.tv_sec)*1e3+(t1.tv_nsec-t0.tv_nsec)/1e6;
    int ok = !m && ms < 50; printf("%s ** bomb: %.3f ms\n", ok?"ok  ":"FAIL", ms); if(!ok) fails++;
    ok = pw_match_domain("**.b.**.d", "a.b.c.d", false) && !pw_match_domain("**.b.**.d", "b.c.d", false)
         && pw_match_domain("a*.b", "abc.b", false) && pw_match_domain("x.**", "x.y.z", false) && !pw_match_domain("x.**", "x", false);
    printf("%s glob semantics\n", ok?"ok  ":"FAIL"); if(!ok) fails++; }

  printf("%s\n", fails?"FAILED":"ALL OK"); pw_engine_destroy(e);

  // more than 256 matching rules: a later app block must still be found (no candidate cap)
  { char path[]="/tmp/pw_many_XXXXXX"; int fd=mkstemp(path); FILE *f=fdopen(fd,"w");
    for(int i=0;i<400;i++) fprintf(f,"R\t%d\t0\t0\t-1\t0\t0\tD\t**.c*m%s\t0\t0\t0\n", 1000+i, i%2?"":"");
    fprintf(f,"R\t9\t1\t2\t10500\t1\t0\tA\t-\t0\t0\t0\n"); fclose(f);
    pw_engine_t *m=pw_engine_load(path,err,100); unlink(path);
    chk(m,10500,"8.8.8.8","a.example.com",6,443,0, 1,1,9);   // global allows only cancel global blocks: the app block (rule 401) still applies
    zdtun_ip_t a={0}; zdtun_parse_ip("8.8.8.8",&a);
    pw_query_t q={.uid=10500,.ipver=4,.ip=&a,.host="a.example.net",.proto=6,.port=443};
    pw_verdict_t v=pw_engine_eval(m,&q); int ok=v.matched && v.block && v.ref==9;
    printf("%s 400 wildcard allows, app block still found -> ref=%d\n", ok?"ok  ":"FAIL", v.ref); if(!ok) fails++;
    pw_engine_destroy(m); }

  // hostile list: keys built to collide still load fast (seeded hash)
  { char path[]="/tmp/pw_hash_XXXXXX"; int fd=mkstemp(path); FILE *f=fdopen(fd,"w");
    for(int i=0;i<200000;i++) fprintf(f,"R\t%d\t0\t0\t-1\t1\t0\tD\th%07d.example\t1\t0\t0\n", i+1, i); fclose(f);
    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    pw_engine_t *m=pw_engine_load(path,err,100); unlink(path);
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double ms=(t1.tv_sec-t0.tv_sec)*1e3+(t1.tv_nsec-t0.tv_nsec)/1e6;
    chk(m,1,"8.8.8.8","x.h0123456.example",6,443,0, 1,1,123457);
    printf("%s 200k rules loaded in %.0f ms\n", ms<5000?"ok  ":"FAIL", ms); if(ms>=5000) fails++;
    pw_engine_destroy(m); }

  printf("%s\n", fails?"FAILED":"ALL OK (extra)"); return fails;
}
