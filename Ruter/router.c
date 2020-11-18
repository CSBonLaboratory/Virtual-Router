#include "skel.h"
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include "queue.h"
#include <net/ethernet.h>
/* ether_header */
#include <arpa/inet.h>
/* icmphdr */
#include <netinet/ip_icmp.h>
/* arphdr */
#include <net/if_arp.h>
#include <asm/byteorder.h>
/* ether_arp */
#include<netinet/if_ether.h>
typedef struct rtable
{
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
	
}r_table;

typedef struct arptable
{
	uint32_t ip;
	u_char mac[6]; 
}arp_table;
    
    r_table *table;
	arp_table *a_table;
	int rtable_size=0;
	int arptable_size=0;

	uint16_t ip_checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

  uint32_t string_to_ip(char *str)
  {
	  uint32_t number=0;
	  char s[4];
	  int k=0,a,len=strlen(str);

	  
      for(int i=0;i<len;i++)
	  {
          while(str[i]!='.' && str[i]!='\0')
		  {
             s[k]=str[i];
			 k++;
			 i++;
		  }
		 number=number<<8;
         s[k]='\0';
		 a=atoi(s);
		 number=number|a;
		 k=0;

	  }

	  return number;

  }
  int read_rtable()
  {
	  FILE *f;
      f=fopen("rtable.txt","rt");

	  if(f==NULL)
	  {
		  printf("Eroare citire router table");
		  exit(1);
	  }

	  char str[50];

      fscanf(f,"%s",str);   // prefix de pe linia 0 
	  table[0].prefix=string_to_ip(str);   // converteste in numar

	  printf("%u\n",table[0].prefix);
      
	  fscanf(f,"%s",str);   // next_hop de pe linia 0
	  table[0].next_hop=string_to_ip(str);
	  printf("%u\n",table[0].next_hop);

      fscanf(f,"%s",str);   
	  table[0].mask=string_to_ip(str);
	  printf("%u\n",table[0].mask);

	  fscanf(f,"%d",&table[0].interface);
	  printf("%u\n",table[0].interface);

	  
	  int i;

	  for(i=1;;i++)
	  {
		  table=(r_table*)realloc(table,(i+1)*sizeof(r_table));
          fscanf(f,"%s",str);
		  table[i].prefix=string_to_ip(str);
		  

		  fscanf(f,"%s",str);
		  table[i].next_hop=string_to_ip(str);
		  

		  fscanf(f,"%s",str);
		  table[i].mask=string_to_ip(str);
		  

		  if(fscanf(f,"%d",&table[i].interface)==EOF)
		  break;
          
		  printf("%u %u %u %d\n",table[i].prefix,table[i].next_hop,table[i].mask,table[i].interface);

	  }

	  printf("%u\n",i);

	  fclose(f);

	  return i;

    

  }
    r_table *get_best_route_fast(uint32_t dest_ip)
	{
		int right=0,left=rtable_size-1,mid;
        
		

		while(left<=right)
		{
			mid=(left+right)/2;
			if((table[mid].prefix & table[mid].mask)==(dest_ip & table[mid].mask))
			return &table[mid];

			if((dest_ip & table[mid].mask)<(table[mid].prefix & table[mid].mask))
			{
                right=mid-1;
			}
			else if((dest_ip & table[mid].mask)>(table[mid].prefix & table[mid].mask))
			{
				left=mid+1;
			}
			
		}

		return NULL;
	}
    r_table *get_best_route(uint32_t dest_ip) {
	
	int max_bits = 0;
	int pos = -1;
	for (int i = 0; i < rtable_size; ++i) {
		if (__builtin_popcount(table[i].mask) > max_bits && 
			((table[i].prefix & table[i].mask) == (dest_ip & table[i].mask))) {
			max_bits = __builtin_popcount(table[i].mask);
			pos = i;
		}
	}
	if (pos == -1) {
		return NULL;
	}
	
	return &table[pos];
}

    uint32_t string_to_ipv4(u_char* sir)   // transforma din uchar[4] in __u32
	{
       uint32_t number=0;

       
	   
	   int i;

	  for(i=0;i<4;i++)
	  {
		  number=number<<8;
		  number=number | sir[i];

		  
	  }
	   return number;

	}

	void string_to_uchar(char *sir,u_char addr[4])  // transforma din 192.168.0.1 in [192][168][0][1]
	{
		u_char number=0,k=0;

		for(int j=0;j<strlen(sir);j++)
		{
			while(sir[j]!='.' && sir[j]!='\0')
			{
				number=number*10+(sir[j]-'0');
				j++;
			}
			addr[k]=number;
			number=0;
			k++;
		}
	}

	void number_to_uchar(uint32_t number,u_char addr[4])   // transforma din uint32_t in uchar[4]
	{
		uint32_t mask=0xff000000;
        uint32_t result;
		for(int i=0;i<4;i++)
		{
           result=number & mask;
		   result=result>>8*(3-i);
		   addr[i]=result;
		   mask=mask>>8;
		   result=0;
		}
	}

	void add_arp(uint32_t sender_ip,u_char* sender_mac)
	{
		a_table[arptable_size].ip=sender_ip;
		memcpy(a_table[arptable_size].mac,sender_mac,6);

		arptable_size++;

		a_table=(arp_table*)realloc(a_table,(arptable_size+1)*sizeof(arp_table));
	}

	arp_table* search_arp(__uint32_t target_ip)
	{
		int i;

		for(i=0;i<arptable_size;i++)
		{
			if(a_table[i].ip==target_ip)
			return &a_table[i];
		}

		return NULL;
	}
   
   queue q;

   int comparator(const void *a,const void *b)
   {
	   r_table* l=(r_table*)a;
	   r_table* r=(r_table*)b;

	   if(l->prefix==r->prefix)

	       return l->mask-r->mask;
	   else
	   
		   return l->prefix-r->prefix;
	   
	   
   }

int main(int argc, char *argv[])
{

	setvbuf(stdout,NULL,_IONBF,0);
	packet m;
	int rc;

	

	q=queue_create();

	init();
	

	table=(r_table*)malloc(sizeof(r_table));
	a_table=(arp_table*)malloc(sizeof(arp_table));
	rtable_size=read_rtable();

     qsort(table,rtable_size-1,sizeof(r_table),comparator);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header*)m.payload;

		

		switch(ntohs(eth_hdr->ether_type))
		{
			case ETHERTYPE_ARP:   ;


			//ARP

            // extrage headerul ether_arp
			struct ether_arp *eth_arp_hdr=(struct ether_arp*)(m.payload + sizeof(struct ether_header));

            if(ntohs(eth_arp_hdr->ea_hdr.ar_op)==ARPOP_REQUEST)
			{
			            
			//pachetul primit o sa fie de tip request, deci va trimite reply

			//adauga in tabela_arp macul sursei ce a trimis requestul
			uint32_t sender_ip=string_to_ipv4(eth_arp_hdr->arp_spa);
		    add_arp(sender_ip,eth_arp_hdr->arp_sha);


            // mac destinatie e macul hostului
		    memcpy(eth_hdr->ether_dhost,eth_hdr->ether_shost,6);

			// mac sursa este macul interfetei routerului
			get_interface_mac(m.interface,eth_hdr->ether_shost);

			u_char aux[6];
            
			//interschimb tpa cu spa
			memcpy(aux,eth_arp_hdr->arp_spa,4);
            
			memcpy(eth_arp_hdr->arp_spa,eth_arp_hdr->arp_tpa,4);

			memcpy(eth_arp_hdr->arp_tpa,aux,4);

			// schimb tha si sha

			memcpy(eth_arp_hdr->arp_tha,eth_arp_hdr->arp_sha,6);

			get_interface_mac(m.interface,eth_arp_hdr->arp_sha);


			 // schimbat din ARP REQUEST in ARP REPLY 
			 eth_arp_hdr->ea_hdr.ar_op=htons(ARPOP_REPLY);   // 2 cod arp_reply


             //trimite REPLY
			 send_packet(m.interface,&m);

			}
			else     // este un pachet de tip ARP reply deci trimite  pachetul din coada daca exista
			{
				

				printf("%d\n",ntohs(eth_arp_hdr->ea_hdr.ar_op));


				// transforma ip sursa a reply-ului din u_char[4] in uint32_t
				uint32_t ip_sender=string_to_ipv4(eth_arp_hdr->arp_spa);

				// adauga in tabela arp macul sursei reply-ului 

				add_arp(ip_sender,eth_arp_hdr->arp_sha);

				
				if(queue_empty(q)==0)  //avem pachet in coada deci trimite forward
                {
                packet *fwd;

				printf("A\n");

				fwd=(packet*)queue_deq(q);

				printf("B\n");
				

                // extrage headerele si ip ethernet al pachetului ce va fi trimis trimis mai departe
				struct ether_header *fwd_eth_hdr=(struct ether_header*)fwd->payload;
				struct iphdr *fwd_ip_hdr=(struct iphdr*)(fwd->payload+sizeof(struct ether_header));
				struct icmphdr *fwd_icmp_hdr=(struct icmphdr*)(fwd->payload+sizeof(struct ether_header)+sizeof(struct iphdr));
				
				printf("%u %u %u %u %u %u\n",
				fwd_eth_hdr->ether_shost[0],
				fwd_eth_hdr->ether_shost[1],
				fwd_eth_hdr->ether_shost[2],
				fwd_eth_hdr->ether_shost[3],
				fwd_eth_hdr->ether_shost[4],
				fwd_eth_hdr->ether_shost[5]
				);

				printf("FWD T %u\n",ntohl(fwd_ip_hdr->daddr));
				printf("FWD S %u\n",ntohl(fwd_ip_hdr->saddr));

				// pune macul destinatie adica cel transmis de reply

				memcpy(fwd_eth_hdr->ether_dhost,eth_arp_hdr->arp_sha,6);


				//updateaza checksum
				//fwd_ip_hdr->check=0;
				//fwd_icmp_hdr->checksum=0;
				//fwd_ip_hdr->check=ip_checksum(fwd_ip_hdr,sizeof(struct iphdr));
				//fwd_icmp_hdr->checksum=ip_checksum(fwd_icmp_hdr,sizeof(struct icmphdr));

				//trimite pachetul mai departe

				printf("C\n");

				int gigel;
				gigel=send_packet(fwd->interface,fwd);
				printf("%d\n",gigel);
				}


			}
			 
			break;

			case ETHERTYPE_IP: ;

			// scoate headerul de ip
			struct iphdr *ip_hdr =(struct iphdr*)(m.payload + (sizeof (struct ether_header)));

			struct icmphdr *icmp_hdr=(struct icmphdr*)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

			//verifica ttl
			if(ip_hdr->ttl<=1)
			continue;
			else
			{
			   ip_hdr->ttl--;
			}

			//verifica checksum
           //uint16_t old_checksum=ip_hdr->check;
		   //ip_hdr->check=0;
		   //icmp_hdr->checksum=0;
		   //if(old_checksum!=ip_checksum(ip_hdr,sizeof(struct iphdr)))
		   //continue;

		   // verifica daca pachetul ip este destinat routetului si trimite ICMP REPLY
		   char* sir_ip;
		   sir_ip=get_interface_ip(m.interface);

		   if(string_to_ip(sir_ip)==ntohl(ip_hdr->daddr) && icmp_hdr->type==ICMP_ECHO)
		   {
			   // interschimba adresele MAC sursa si destinatie
			   u_char aux[4];

			   memcpy(aux,eth_hdr->ether_shost,6);
			   memcpy(eth_hdr->ether_shost,eth_hdr->ether_dhost,6);
			   memcpy(eth_hdr->ether_dhost,aux,6);

			   //interschimba adresele ip sursa si ip destinatie
			   uint32_t aux_ip;

			   aux_ip=ip_hdr->saddr;
			   ip_hdr->saddr=ip_hdr->daddr;
               ip_hdr->daddr=aux_ip;

               // schimba tipul ICMP-ului in REPLY
			   icmp_hdr->type=ICMP_ECHOREPLY;
			   icmp_hdr->code=0;

               // updateaza checksum
			   //ip_hdr->check=ip_checksum(ip_hdr,sizeof(struct iphdr));
			   //icmp_hdr->checksum=ip_checksum(icmp_hdr,sizeof(struct icmphdr));

			   send_packet(m.interface,&m);

			   continue;

		   }
		   

			

			uint32_t target_ip=ntohl(ip_hdr->daddr);

			arp_table *arp_entry=search_arp(target_ip);  // cauta o intrare in tabela ARP

			r_table *entry = get_best_route(target_ip);  // cauta cea mai buna ruta in tabela de routare

			if(entry==NULL)   // nu a gasit nicio intrare valida deci dhost unreachable
			{
				icmp_hdr->type=ICMP_DEST_UNREACH;
				icmp_hdr->code=ICMP_HOST_UNREACH;

				// interschimba adresele MAC sursa si destinatie
			   u_char aux[4];

			   memcpy(aux,eth_hdr->ether_shost,6);
			   memcpy(eth_hdr->ether_shost,eth_hdr->ether_dhost,6);
			   memcpy(eth_hdr->ether_dhost,aux,6);

			   //adresa destinatie va fi adresa sursa a hostului care a trimis pachet
			   ip_hdr->daddr=ip_hdr->saddr;

               // adresa ip sursa este adresa interfetei 
			   char* str_ip;
			   str_ip=get_interface_ip(m.interface);
			   ip_hdr->saddr=htonl(string_to_ip(str_ip));  // transforma din char* in uint32_t si apoi in big endian


			   send_packet(m.interface,&m);

			   continue;


			}

			// adresa MAC sursa va fi adresa mac a interfetei pe care trimite pachetul
            get_interface_mac(entry->interface,eth_hdr->ether_shost);


            if(arp_entry==NULL)  // nu a gasit in tabela arp un MAC asociat ip-ului destinatie deci trimite request
			{
				packet req,copie;

                // initializeaza headere pt request
				struct ether_header *new_eth_hdr=(struct ether_header*)malloc(sizeof(struct ether_header));

				struct ether_arp *new_eth_arp_hdr=(struct ether_arp*)malloc(sizeof(struct ether_arp));

				struct arphdr *new_arp_hdr=(struct arphdr*)malloc(sizeof(struct arphdr));
                
				
                // tip pachet ARP
			    new_eth_hdr->ether_type=htons(ETHERTYPE_ARP);

                //MAC sursa este macul interfetei routerului pe care trimit
				get_interface_mac(entry->interface,new_eth_hdr->ether_shost);

				// sha din ether_arp
				memcpy(new_eth_arp_hdr->arp_sha,new_eth_hdr->ether_shost,6);

				// spa din ether_arp
				string_to_uchar(get_interface_ip(entry->interface),new_eth_arp_hdr->arp_spa);

				// tpa din ether_arp
				number_to_uchar(ntohl(ip_hdr->daddr),new_eth_arp_hdr->arp_tpa);

				// hardware format din arphdr
				new_arp_hdr->ar_hrd=htons(ARPHRD_ETHER);

                //protocol format din arphdr de tip IP
				new_arp_hdr->ar_pro=htons(0x0800);

				// length of hardware adress din arphdr
				new_arp_hdr->ar_hln=6;

				//length of protocol adress din arphdr
				new_arp_hdr->ar_pln=4;

				// operation
				new_arp_hdr->ar_op=htons(ARPOP_REQUEST);

                // ea_hdr din ether_arp
				new_eth_arp_hdr->ea_hdr=*new_arp_hdr;

				// asamblare pachet
				memcpy(req.payload,new_eth_hdr,sizeof(struct ether_header));

				memcpy(req.payload+sizeof(struct ether_header),new_eth_arp_hdr,sizeof(struct ether_arp));

				req.interface=entry->interface;
				
				req.len=58;   // marime arp_request

                
				

                // face o copie a pachetului IP si il pune in coada

				m.interface=entry->interface;

				copie.interface=m.interface;

				copie.len=m.len;
            
                
				//asambleaza pachetul ip/icmp copie
				memcpy(copie.payload,eth_hdr,sizeof(struct ether_header));

				memcpy(copie.payload+sizeof(struct ether_header),ip_hdr,sizeof(struct iphdr));

				memcpy(copie.payload+sizeof(struct ether_header)+sizeof(struct iphdr),icmp_hdr,sizeof(struct icmphdr));

				printf("a bagat\n");

				struct ether_header *copy_ether=(struct ether_header*)copie.payload;
				struct iphdr *copy_ip=(struct iphdr*)(copie.payload+sizeof(struct ether_header));
				struct icmphdr *copy_icmp=(struct icmphdr*)(copie.payload+sizeof(struct iphdr));

				queue_enq(q,&copie);


				printf("M %u %u %u %u %u %u\n",
				eth_hdr->ether_shost[0],
				eth_hdr->ether_shost[1],
				eth_hdr->ether_shost[2],
				eth_hdr->ether_shost[3],
				eth_hdr->ether_shost[4],
				eth_hdr->ether_shost[5]
				);

				

				printf("COPIE %u %u %u %u %u %u\n",
				copy_ether->ether_shost[0],
				copy_ether->ether_shost[1],
				copy_ether->ether_shost[2],
				copy_ether->ether_shost[3],
				copy_ether->ether_shost[4],
				copy_ether->ether_shost[5]
				);

				printf(" IP t copie%u \n",ntohl(copy_ip->daddr));

				printf(" IP s m %u\n",ntohl(ip_hdr->saddr));

				printf("IP s copie %u\n",ntohl(copy_ip->saddr));

				//trimite request

                send_packet(req.interface,&req);

               
			}
			else
		    {
                printf("arp gasit\n");
			// forward packet cu MAC-ul luat din tabela de routare
                
				

                // adresa MAC a destinatiei va fi adresa mac din tabela de routare
				memcpy(eth_hdr->ether_dhost,arp_entry->mac,6);

                //updateaza checksum
				//ip_hdr->check=0;
                //icmp_hdr->checksum=0;
				//ip_hdr->check=ip_checksum(ip_hdr,sizeof(struct iphdr));

				//icmp_hdr->checksum=ip_checksum(icmp_hdr,sizeof(struct icmphdr));

				int dorel=send_packet(entry->interface,&m);

				printf("%d\n",dorel);


               

			}

            break;


			default:
			printf("ALT TIP\n");
		
		}
 
    
	
	}
}
