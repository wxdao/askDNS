#include <iostream>
#include <winsock2.h>
#include <vector>
#include <stdio.h>
#include <map>

using namespace std;

#define prt(x) std::cout<<x<<std::endl<<std::flush
#define inp(x) std::cin>>x

#define FASTADDR(a,x,y,z) ((sockaddr_in*)&a)->sin_family=x;\
  ((sockaddr_in*)&a)->sin_addr.s_addr=inet_addr(y);\
  ((sockaddr_in*)&a)->sin_port=htons(z)

#define FASTADDR_ANY(a,x,z) ((sockaddr_in*)&a)->sin_family=x;\
  ((sockaddr_in*)&a)->sin_addr.s_addr=INADDR_ANY;\
  ((sockaddr_in*)&a)->sin_port=htons(z)

#define INITWSA  \
  WORD wVersionRequested;\
  WSADATA wsaData;\
  wVersionRequested=MAKEWORD(1, 1);\
  WSAStartup(wVersionRequested, &wsaData)

#define GOOD_TAG 0x8180

sockaddr mdns;

struct dns_header
{
  short ID;
  short TAG;
  short QDCOUNT;
  short ANCOUNT;
  short NSCOUNT;
  short ARCOUNT;
};

struct dns_question
{
  short QTYPE;
  short QCLASS;
};

struct dns_resource
{
  short RTYPE;
  short RCLASS;
  long  TTL;
  u_short RDLENGTH;
};

std::vector<string> splitstr(string str,char c)
{
  u_long c_pos=0;
  u_long pre=-1;
  vector<string> res;
  while(c_pos!=str.npos)
    {
      c_pos=str.find(c,c_pos+1);
      res.push_back(str.substr(pre+1,c_pos-pre-1));
      pre=c_pos;
    }
  return res;
}

void encodehn(string source,char *dest,int *len)
{
  memset(dest,0,*len);
  char label;
  string tmp;
  vector<string> hostl = splitstr(source,'.');
  for(string i : hostl)
    {
      label=i.length();
      tmp+=label;
      tmp+=i;
    }
  strcpy(dest,tmp.c_str());
  *len=tmp.length()+1;
}

string gethostn(char *pos,int *len)
{
  char *n=pos;
  string res;
  while(*n!=0)
    {
      int len = *n;
      for(int i=1;i<=len;++i)
        {
          res += *(n+i);
        }
      n+=len+1;
      res += '.';
    }
  res.at(res.length()-1)=0;
  res.erase(res.length()-1);
  *len=(int)(n+1-pos);
  return res;
}
struct hdata
{
  char a;
  char b;
  char c;
  char d;
};

vector<string> shlist = {"wide.sense"};
map<string,hdata> shmap;

void gethimone(SOCKET dns_fd,sockaddr *cli,char *buf,int len,string hostn)
{
  ((dns_header*)buf)->TAG=htons(GOOD_TAG);
  ((dns_header*)buf)->ANCOUNT=1;
  dns_resource r;
  memset(&r,0,sizeof(r));
  r.TTL=50;
  r.RTYPE=htons(1);
  r.RCLASS=htons(1);
  r.RDLENGTH=htons(4);
  memmove(buf+len,&r,sizeof(r));
  memmove(buf+len+sizeof(r),&(shmap[hostn]),4);
  sendto(dns_fd,buf,len+sizeof(r)+4,0,cli,sizeof cli);
}

void fuckhimaway(SOCKET dns_fd,sockaddr *cli,char *buf,int len)
{
  SOCKET sck= socket(AF_INET,SOCK_DGRAM,0);
  int timeout = 3000;
  setsockopt(sck,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
  sendto(sck,buf,len,0,&mdns,sizeof(mdns));
  char buf2[1024]={0};
  int glen=recvfrom(sck,buf2,1024,0,NULL,NULL);
  if(glen>0)
    {
      sendto(dns_fd,buf2,glen,0,cli,sizeof cli);
    }
}

bool checkthere(string hostn)
{
  for(string i : shlist)
    {
      if(hostn==i)
        return true;
    }
  return false;
}


int main()
{

  INITWSA;
  SOCKET dns_fd= socket(AF_INET,SOCK_DGRAM,0);
  int timeout = 3000;
  setsockopt(dns_fd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));

  dns_header h;
  memset(&h,0,sizeof h);
  h.ID=htons(0x5617);
  h.TAG=htons(0x0100);
  h.QDCOUNT=htons(1);

  dns_question q;
  q.QCLASS=htons(1);
  q.QTYPE=htons(1);

  string toask="wide.sense";
  char toask_r[24]={0};
  int len=24;
  encodehn(toask,toask_r,&len);
  int shit;
  prt(checkthere(gethostn(toask_r,&shit)));
  prt(shlist[0]);

  int buf_size=sizeof(h)+sizeof(q)+len;
  char buf[1024];
  memset(buf,0,1024);
  memmove(buf,&h,sizeof(h));
  memmove(buf+sizeof(h),toask_r,len);
  memmove(buf+sizeof(h)+len,&q,sizeof(q));

  sockaddr todnss;
  FASTADDR(todnss,AF_INET,"220.173.159.235",53);

  int tlen;
  tlen = sendto(dns_fd,buf,buf_size,0,&todnss,sizeof(sockaddr));
  prt(tlen);

  int addr_len=sizeof(sockaddr);
  char buf2[1024] = {0};
  tlen = recvfrom(dns_fd,buf2,1024,0,&todnss,&addr_len);
  prt(tlen);


  int get = ntohs(((dns_header*)buf2)->ANCOUNT);
  prt(get);
  char* p = buf2 + tlen -4;
  printf("%u.%u.%u.%u\n",(unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
  prt(((dns_header*)buf2)->ID);
  prt(ntohs(18467));

  return 0;
}
