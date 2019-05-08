#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#define SIZE 10
#define CYA -1
#define CANNOT_TELL -2
#define MALLOC_ERROR -3
#define FREE_ERROR -4
#define SHOW_ERROR -5
typedef struct {
	char * str;
	unsigned int size;
} item;
item items[SIZE];
void main_menu() {
	puts("-----Yet Another Babyheap!-----");
	puts("[M]alloc ");
	puts("[F]ree ");
	puts("[S]how ");
	puts("[E]xit ");
	puts("------------------------");
	printf("Command:\n> ");
}
int get_atoi() {
	char buf[4]="";
	read(0,buf,4);	
	return atoi(buf);
}
int malloc_1() {
	unsigned int index, i;
	unsigned int size;
	char ch;
	for (index=0; index<=SIZE; index++)
		if (items[index].str==NULL) break;
	if (index >= SIZE) return MALLOC_ERROR;
	printf("Size:\n> ");
	size = get_atoi();
	if (size > 0x178 || size <= 0)
		return MALLOC_ERROR;
	else if (size > 0xf8)
		items[index].str = (char *) malloc(0x178);
	else
		items[index].str = (char *) malloc(0xf8);
	if (items[index].str == NULL) return MALLOC_ERROR;	
	items[index].size = size; // this cannot be changed
	printf("Content:\n> ");
	// safe_read(items[i].str, items[i].size);
	//str[size]='\0'; this can be on
	i = 0;
	while(1) {
		read(0, &ch, 1);
		if (i>size || ch=='\0' || ch=='\n' || ch==0x81 || ch==0x80) // this is the key to overwrite 1 byte
			break;
		items[index].str[i++] = ch;
	}
	// items[index].str[i]='\0';  // this is the point to leak libc address and must be removed 
	return 0;
}
int free_1() {
	unsigned int index;
	puts("(Starting from 0) Index:\n> ");
	index=get_atoi();
	if (index>=SIZE || items[index].str==NULL)
		return FREE_ERROR;	
	memset(items[index].str, 0, items[index].size);
	free(items[index].str);
	items[index].size=0;
	items[index].str=NULL;
	return 0;	
}
int show_1() {
	unsigned int index;
	printf("(Starting from 0) Index:\n> ");
	index=get_atoi();
	if(index>=10 || items[index].str==NULL)
		return SHOW_ERROR;	
	puts(items[index].str);
	return 0;
}

void triage(int value){
	switch(value) {
		case CYA: puts("Done"); break;
		case CANNOT_TELL: puts("Command Error"); break;
		case MALLOC_ERROR: puts("Malloc Error"); break;
	        case SHOW_ERROR: puts("Show Error"); break;
	        case FREE_ERROR: puts("Free Error"); break;
		default: puts("Unknown Error"); break;
	}
	exit(0);
}

int is_valid(int value) {
	if (value == 0) return 1;
	else return 0;
}

int loop() {
	int value = CYA;
	char command[2] = "";
	while(1) {
		main_menu();
	        read(0,&command,2);	
		switch(command[0]) {
			case 'M':
				value = malloc_1();
				break;
			case 'F':
				value = free_1();
				break;
			case 'S':
				value = show_1();
				break;
			case 'E':
				value = CYA;
				break;
			default:
				value = CANNOT_TELL;
				break;		
		}
		if (is_valid(value) == 0) break;
	}
	triage(value);
	return 0;
}

int main(void) {
	setvbuf(stdout,0LL,2,0LL);
        setvbuf(stdin,0LL,1,0LL);
        setvbuf(stderr, 0LL, 2, 0LL);
	// TODO: proof of work?
	loop();
	return 0;
}
