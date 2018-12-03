#include <stdint.h>
#include <byteswap.h>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sched.h>
#include <getopt.h>
#include <termios.h>


#define SIMULATE_HEATER 1

uint8_t stop = 0;

char t1_path[255] = "/dev/ttyUSB0";
char t2_path[255] = "/dev/ttyUSB1";
char pcap_path[255] = "/tmp/serial.pcap";
uint8_t pcap_debug = 0;
uint32_t tty_speed=57600;

#define MAX_BUF 256
int t1_fd=0, t2_fd=0;

#define MIN_PACKET_SIZE 7
struct S_PACKET {
    uint8_t preamble; //0xAA
    uint8_t device; //0x03 controller, 0x04 heater
    uint8_t len; //payload
    uint8_t msg_id1;
    uint8_t msg_id2; 
    char payload[255];
    uint16_t crc;
};

char *printHEX(const uint8_t *s, int len) {
	static char buf[0xFF];
        int i;

	if (len>(0xFF/3)) {  //3 bytes for every character in s
		sprintf(buf,"[STRING TOO LONG]\0");
		return buf;
	}

        for (i = 0; i < len; ++i) sprintf(buf+(3*i),"%02x ", s[i]);
	buf[3*i] = '\0';

	return buf;
}

uint16_t CRC16(char *buf, uint8_t len)
{
  uint16_t crc = 0xFFFF;
  uint8_t pos;
  uint8_t i;

  for (pos = 0; pos < len; pos++)
  {
    crc ^= (uint8_t)buf[pos];          // XOR byte into least sig. byte of crc

    for (i = 8; i != 0; i--) {    // Loop over each bit
      if ((crc & 0x0001) != 0) {      // If the LSB is set
        crc >>= 1;                    // Shift right and XOR 0xA001
        crc ^= 0xA001;
      }
      else                            // Else LSB is not set
        crc >>= 1;                    // Just shift right
    }
  }
  return crc;
}

uint8_t serialize(char *buf, struct S_PACKET *t) {
	uint16_t crc;

	buf[0] = t->preamble;
	buf[1] = t->device;
	buf[2] = t->len;
	buf[3] = t->msg_id1;
	buf[4] = t->msg_id2;
	memcpy(buf+5,t->payload,t->len);

	crc = CRC16(buf,t->len+MIN_PACKET_SIZE-2);
	crc = __bswap_16(crc);
	memcpy(buf+MIN_PACKET_SIZE+t->len-2,&crc,2);

	return t->len+MIN_PACKET_SIZE;
}

void recalc_crc(char *buf,int len) {
	uint16_t c_crc;
	c_crc=CRC16(buf,len-2);
	c_crc = __bswap_16(c_crc); //reverse byte order
	memcpy(buf+len-2,&c_crc,2);
}


uint8_t _parse(struct S_PACKET *t, char *buf, int len) { //parse buf into t; returns 0 if no packet found otherwise returns number of bytes consumed
	uint8_t i = 0;
	uint16_t crc;
	uint16_t c_crc;
	uint8_t payload_len;
	char *packet;
	uint16_t r_len;
	uint16_t packet_len;

	if (len<MIN_PACKET_SIZE) return 0;

	while (i<=len-MIN_PACKET_SIZE) {
		if (buf[i]!=0xaa) {i++; continue;}
		//we have preamble - check if we have full packet
		packet = buf+i;
		r_len = len-i;

		payload_len = packet[2];
		packet_len = MIN_PACKET_SIZE+payload_len;
		if (r_len<packet_len) {
			//not
			return 0;
		}
		//yes - but check crc
		memcpy(&crc,packet+packet_len-2,2);
		c_crc=CRC16(packet,packet_len-2);
		c_crc = __bswap_16(c_crc); //reverse byte order
		if (crc!=c_crc) {
			printf("incorrect crc!. calculated: %s\n",printHEX(&c_crc,2));
			i++;
			continue;
		}
		
		//all good - we have packet
		t->preamble = packet[0];
		t->device = packet[1];
		t->len = packet[2];
		t->msg_id1 = packet[3];
		t->msg_id2 = packet[4];
		memcpy(t->payload,packet+5,t->len);
		memcpy(&t->crc,packet+packet_len-2,2);
		return i+packet_len;
	}
	return 0;
}

void print(struct S_PACKET *p) {
    if (p->device == 0x03)
        printf("C: ");
    else if (p->device == 0x04)
        printf("H: ");
    else printf("Unknown device (%s) ",printHEX(&p->device,1));

    printf("id1: 0x%s ",printHEX(&p->msg_id1,1));
    printf("id2: 0x%s ",printHEX(&p->msg_id2,1));
    printf("data (%u): %s",p->len,printHEX(p->payload,p->len));
    //printf("len: %u ",p.len);
    //printf("crc: %s ",printHEX(&p.crc,2));

    printf("\n");
}

char r_02[] = "\xaa\x04\x06\x00\x02\x00\x32\x04\x01\x02\x00\x00\x00";
char r_03[] = "\xaa\x04\x00\x00\x03\x00\x00";
char r_06[] = "\xaa\x04\x04\x00\x06\x0a\x3a\x05\x01\x00\x00";
char r_0f[] = "\xaa\x04\x0a\x00\x0f\x00\x01\x14\x15\x7f\x00\x81\x01\x26\x00\x00\x00";
char r_11[] = "\xaa\x04\x01\x00\x11\x7f\x00\x00";
char r_1e[] = "\xaa\x00\x00\x00\x1e\x00\x00";
char r_23[] = "\xaa\x04\x04\x00\x23\x00\x32\x00\x00\x00\x00";

struct S_PACKET *simulate_heater_response(struct S_PACKET *c) {
	static struct S_PACKET p;
	static uint8_t vent = 0;
	switch (c->msg_id2) {
		case 0x02:
			recalc_crc(r_02,sizeof(r_02)-1);
			_parse(&p,r_02,sizeof(r_02)-1);
			break;
		case 0x03: //stop vent
			vent = 0;
			recalc_crc(r_03,sizeof(r_03)-1);
			_parse(&p,r_03,sizeof(r_03)-1);
			break;
		case 0x06: //something wrong?
			recalc_crc(r_06,sizeof(r_06)-1);
			_parse(&p,r_06,sizeof(r_06)-1);
			break;
		case 0x0f: //hello
			if (vent) {
				r_0f[5] = vent;
			}
			else r_0f[5] = 0;
			recalc_crc(r_0f,sizeof(r_0f)-1);
			_parse(&p,r_0f,sizeof(r_0f)-1);
			break;
		case 0x11: 
			recalc_crc(r_11,sizeof(r_11)-1);
			_parse(&p,r_11,sizeof(r_11)-1);
			break;
		case 0x1e: 
			recalc_crc(r_1e,sizeof(r_1e)-1);
			_parse(&p,r_1e,sizeof(r_1e)-1);
			break;
		case 0x23: //request for vent 
			vent = 2;
			recalc_crc(r_23,sizeof(r_23)-1);
			_parse(&p,r_23,sizeof(r_23)-1);
			break;
		defaults:
		    printf("Unknown message!\n");
		    return 0;
	}

	return &p;
}

struct S_PACKET *parse(int src, char *buf, int len) { //parse with accumulator for part data 
		static z = 0;

    static struct S_PACKET p;
    static char s_buf[255];
    static uint8_t s_len = 0;
    uint8_t i;
    uint8_t ret;

    if (s_len+len>=255) {
        printf("Unable to find valid packet! Are you sure serial baud rate is correct?\n");
	s_len = 0;
    }

    for (i=0;i<len;i++)
	    s_buf[s_len++] = buf[i];

   
    ret=_parse(&p,s_buf,s_len);

    if (!ret) return 0; //no packet found

    s_len = 0;

    return &p;

} 

void catch_signal(int sig)
{
    printf("signal: %i\n",sig);
    stop = 1;
}

void print_usage() {
    printf("Usage: %s -a [t1_uart] -b [t2_uart] -s [speed] -d\n",PACKAGE_NAME);
    printf("-h\thelp\n");
    printf("-d\tactivate pcap capture into %s\n",pcap_path);      
    printf("[t1_uart] path to uart 1 [defaults: %s]\n",t1_path);
    printf("[t2_uart] path to uart 2 [defaults: %s]\n",t2_path);
    printf("[speed] serial port speed [defaults: %u]\n",tty_speed);
}

int set_defaults(int c, char **a) {
    int option;
    while ((option = getopt(c, a,"a:b:s:d")) != -1) {
        switch (option)  {
            case 'a': strcpy(t1_path,optarg); break;
            case 'b': strcpy(t2_path,optarg); break;
	        case 's': tty_speed = atoi(optarg); break;
            case 'd': pcap_debug = 1; break;
            default:
                print_usage();
                return -1;
                break;
        }
    }
    return 0;
} 

int fp1 = 0;

void pcap_header(int fp) {
        uint32_t magic_number=0xa1b2c3d4;
        uint16_t version_major=2;
        uint16_t version_minor=4;  /* minor version number */
        int32_t  thiszone=0;       /* GMT to local correction */
        uint32_t sigfigs=0;        /* accuracy of timestamps */
        uint32_t snaplen=65535;        /* max length of captured packets, in octets */
        //uint32_t network=195;        /* data link type */
        uint32_t network=113;        /* data link type */

        write(fp,&magic_number,4);
        write(fp,&version_major,2);
        write(fp,&version_minor,2);
        write(fp,&thiszone,4);
        write(fp,&sigfigs,4);
        write(fp,&snaplen,4);
        write(fp,&network,4);
}

void pcap_packet(int fp, char *buf, int len, int dir) {
    static uint32_t sec=0;
    static uint32_t usec=0;

    struct timeval tv;
    gettimeofday(&tv,NULL);
    sec = tv.tv_sec;
    usec = tv.tv_usec;
/*
    usec += 100;
    if (usec==1000000) {
        sec++;
        usec=0;
    }
*/

    uint32_t ts_sec = sec;
    uint32_t ts_usec = usec;
    uint32_t incl_len=len+16;
    uint32_t orig_len=len+16; 

    write(fp,&ts_sec,4);
    write(fp,&ts_usec,4);
    write(fp,&incl_len,4);
    write(fp,&orig_len,4);

    //packet header
    uint16_t v;
    v=(dir==0?4:0); //0-to us; 4-from us
    v=htons(v);
    write(fp,&v,2);

    v=0;
    write(fp,&v,2);

    v=0; //address length
    write(fp,&v,2);

    uint64_t v1=0; //address
    write(fp,&v1,8);

    v=0; //1-without an 802.2 LLC header
    v=htons(v);
    //v=ntohs(v);
    write(fp,&v,2);

    write(fp,buf,len);
}

void pcap(int s, char *buf, int len) {
    static int init = 0;
    static int site1 = -1;
    if (site1==-1) site1=s;


    if (init==0) {
        fp1 = open("/tmp/serial.pcap",O_WRONLY | O_CREAT, 0777);
        pcap_header(fp1);
        init++;
    }

    if (s==site1) pcap_packet(fp1,buf,len,0);
    else pcap_packet(fp1,buf,len,1);
}

void forward_packet(int s, int t) {
    int len,len1;
    char buf[MAX_BUF];
    struct S_PACKET *p;

    len = read(s,buf,MAX_BUF);
    
    if (len<=0) {
        printf("reading error [%i] [%s]\n",errno,strerror(errno));
        stop = 1;
        return;
    }

    if (pcap_debug) pcap(s,buf,len);

    p = parse(s,buf,len);
    if (!p) return; //no packet found

    //if (p->device==0x00) return;

    if (p->msg_id2==0xf) printf("\n");
    printf(">"); print(p);

    if (SIMULATE_HEATER) { //simulate heater
	    usleep(1200);
	    struct S_PACKET *h;
	    h = simulate_heater_response(p);
	    printf("<"); print(h);
	    len=serialize(buf,h);
	    len1 = write(s,buf,len); //write back to source
    } else { 
	    len=serialize(buf,p);
	    len1 = write(t,buf,len);
    }
            
    if (len!=len1) {
        printf("writing error [%i] [%s]\n",errno,strerror(errno));
        stop = 1;
        return;
    }           
}

void loop() {
    fd_set fdlist,rlist;
    struct timeval tv;
    int ret;

    FD_ZERO(&fdlist);

    FD_SET(t1_fd, &fdlist);
    FD_SET(t2_fd, &fdlist);

    printf("Started. On %s and %s with speed: %u\n",t1_path,t2_path,tty_speed);
    while (!stop) {
        rlist = fdlist;
        tv.tv_sec = 1; 
        tv.tv_usec = 0;

        ret = select (FD_SETSIZE, &rlist, NULL, NULL, &tv);

        if (ret < 0) {
              perror ("select");
              stop = 1;
              return;
        } 

        if (ret == 0) { //timeout
            continue; 
        }

        if (FD_ISSET(t1_fd,&rlist)) {
            forward_packet(t1_fd,t2_fd);
        }

        if (FD_ISSET(t2_fd,&rlist)) {
            forward_packet(t2_fd,t1_fd);
        }
    }  
}

void cleanup() {
    if (fp1) close(fp1);
    if (t1_fd) close(t1_fd);
    if (t2_fd) close(t2_fd);
    printf("Bye.\n");
}

speed_t get_tty_speed(uint32_t v) {
    switch(v) { 
	case 1200: return B1200;
	case 2400: return B2400;
	case 4800: return B4800;
	case 9600: return B9600;
	case 19200: return B19200;
	case 38400: return B38400;
	case 57600: return B57600;
	case 115200: return B115200;
	default: return 0;
    }
}

int uart_open(const char *path, int flags) {
    int ret = open(path, flags);

    if (ret<0) {
        printf("open failed on %s [%i] [%s]\n",path,errno,strerror(errno));
        return ret;
    }

    if (get_tty_speed(tty_speed)==0) {
	printf("Incorrect serial speed: %u\n",tty_speed);
	return -1;
    }

    struct termios options;
    tcgetattr(ret, &options);

    /* ====================== */
    
    options.c_cflag &= ~(CSIZE | PARENB);
    options.c_cflag |= CS8;

    
    options.c_iflag &= ~(IGNBRK | BRKINT | ICRNL |
                     INLCR | PARMRK | INPCK | ISTRIP | IXON);
    
    options.c_oflag = 0;

    
    options.c_lflag &= ~(ECHO | ECHONL | ICANON | IEXTEN | ISIG);



    /* ====================== */
    /*

        options.c_cflag = CRTSCTS | CS8 | CLOCAL | CREAD;
        options.c_iflag = IGNPAR | ICRNL ;
        options.c_oflag = 0;
// Read 256 data values before signal handler is called
        options.c_cc[VMIN]=0;
        options.c_cc[VTIME]=0;
        options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG );
*/
    /* ====================== */

    /*

	options.c_line = 0;

	options.c_iflag |= IGNBRK;
	options.c_iflag |= IGNPAR;
	options.c_iflag &= ~PARMRK;
	options.c_iflag &= ~INPCK;
	options.c_iflag &= ~ISTRIP;
	options.c_iflag &= ~INLCR;
	options.c_iflag &= ~IGNCR;
	options.c_iflag &= ~ICRNL;
	options.c_iflag &= ~IUCLC;
	options.c_iflag &= ~IXON;
	options.c_iflag |= IXANY;
	options.c_iflag &= ~IXOFF;
	options.c_iflag &= ~IMAXBEL;

	options.c_oflag |= OPOST;
	options.c_oflag &= ~OLCUC;
	options.c_oflag &= ~ONLCR;
	options.c_oflag &= ~OCRNL;
	options.c_oflag |= ONOCR;
	options.c_oflag &= ~ONLRET;
	options.c_oflag &= ~OFILL;
	options.c_oflag &= ~OFDEL;

	options.c_cflag &= ~CSIZE;
	options.c_cflag |= CS8;
	options.c_cflag &= ~CSTOPB;
	options.c_cflag |= CREAD;

	options.c_cflag &= ~PARENB;
	options.c_cflag &= ~PARODD;

	options.c_cflag &= ~HUPCL;
	options.c_cflag |= CLOCAL;
	options.c_cflag &= ~CRTSCTS;

	options.c_lflag &= ~ISIG;
	options.c_lflag &= ~ICANON;
	options.c_lflag &= ~ECHO;
	options.c_lflag |= IEXTEN;

	options.c_cc[VMIN] = 0;
	options.c_cc[VTIME] = 0;
*/

    if(cfsetispeed(&options, get_tty_speed(tty_speed)) < 0 || cfsetospeed(&options,
	get_tty_speed(tty_speed)) < 0) {
        return -1;
    }

    tcflush(ret, TCIFLUSH);
    tcsetattr(ret, TCSANOW, &options);
    return ret; 
}

int main(int argc, char **argv) {

    signal(SIGTERM, catch_signal);
    signal(SIGINT, catch_signal);

//    setbuf(stdout, NULL);

    if (set_defaults(argc,argv)) return -1;

    t1_fd = uart_open(t1_path, O_RDWR | O_NOCTTY | O_SYNC | O_NDELAY | O_NONBLOCK);
    if (t1_fd<0) {
        cleanup();
        return -1;
    }

    t2_fd = uart_open(t2_path, O_RDWR | O_NOCTTY | O_SYNC | O_NDELAY | O_NONBLOCK);
    if (t2_fd<0) {
        cleanup();
        return -1;
    }

    loop();

    cleanup();

    return 0;
}

