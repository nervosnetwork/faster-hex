#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern const unsigned char loop_a16[],loop_a32[],loop_a48[],loop_b16[],loop_b32[],loop_b48[];
extern size_t scan_at(const unsigned char*,size_t,const unsigned char*,const void*);
static const unsigned char *const variants[]={loop_a16,loop_a32,loop_a48,loop_b16,loop_b32,loop_b48};
static const unsigned char reference[]={0x48,0x8d,0x0c,0x28,0x48,0x83,0xf9,0xff,0x74,0x1e,0x41,0x0f,0xb6,0x4c,0x2d,0x01,0x48,0xff,0xc5,0x80,0x3c,0x0b,0xff,0x75,0xe7};
static uint64_t now(void){
    struct timespec t;int err=clock_gettime(CLOCK_MONOTONIC_RAW,&t);assert(err==0);
    return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;
}
int main(int argc,char **argv){
    unsigned char table[256],text[128];
    memset(table,255,sizeof table);
    for(unsigned i=0;i<10;i++)table['0'+i]=i;
    for(unsigned i=0;i<6;i++)table['a'+i]=table['A'+i]=i+10;
    memset(text,'A',sizeof text);
    const int offsets[]={16,32,48,16,32,48};
    for(int i=0;i<6;i++){
        assert(((uintptr_t)variants[i]&63)==(uintptr_t)offsets[i]);
        assert(memcmp(variants[i],reference,sizeof reference)==0);
    }
    if(argc==1){
        for(int v=0;v<6;v++)for(unsigned n=0;n<=128;n++){
            assert(scan_at(text,n,table,variants[v])==n);
            for(unsigned pos=0;pos<n;pos++){
                text[pos]=255;assert(scan_at(text,n,table,variants[v])==pos);text[pos]='A';
            }
        }
        return 0;
    }
    assert(argc==5);
    unsigned n=atoi(argv[1]),bad=atoi(argv[2]),which=atoi(argv[3]),count=atoi(argv[4]);
    assert(n<=sizeof text && bad<=n && which<6 && count>0);
    if(bad<n)text[bad]='!';
    size_t sum=0;
    for(unsigned i=0;i<count/5+1;i++)sum+=scan_at(text,n,table,variants[which]);
    size_t warm=sum;
    uint64_t start=now();
    for(unsigned i=0;i<count;i++)sum+=scan_at(text,n,table,variants[which]);
    uint64_t elapsed=now()-start;
    assert(sum-warm==(size_t)count*bad);
    printf("%.6f\n",(double)elapsed/count);
}
