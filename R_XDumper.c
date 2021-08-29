#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/types.h>
#include <memory.h>

#define DUMP_FILE "mydump.dmp"


typedef struct mem_region_entry {
	unsigned long long addr;
	unsigned int size;
	unsigned int type;
	unsigned  int inode;
	unsigned int protect;
	char *filename;

} mem_region_entry;

int startswith(const char *a, const char *b)
{
    if(strncmp(a, b, strlen(b)) == 0) {
        return 1;
    }
    return 0;
}
void dump_mem_region(mem_region_entry region, FILE *mem_fp, FILE *dump_fp)
{
 if (region.protect == PROT_NONE) {
        return;
    }

   if (region.inode!=0 && region.protect == PROT_READ) {
        return;
    }
    
    
if (region.filename != NULL &&
        (startswith(region.filename, "/usr/lib/x86_64-linux-gnu") || 
         startswith(region.filename, "/usr/libexec/gnome-session-ctl") ||
         startswith(region.filename, "/usr/lib/locale/locale-archive") ||
         startswith(region.filename, "/usr/lib/systemd"))){
        return;
    }
int state = 0;

if(region.protect==5 /*&& region.inode==0*/){       
fwrite(&region.addr, sizeof(unsigned long long), 1, dump_fp);
fwrite(&region.size, sizeof(unsigned int), 1, dump_fp);
fwrite(&state, sizeof(unsigned int), 1, dump_fp);
fwrite(&region.type, sizeof(unsigned int), 1, dump_fp);
fwrite(&region.protect, sizeof(unsigned int), 1, dump_fp);

unsigned long current_address = region.addr;
unsigned long end_address = region.addr + region.size;
unsigned char page[PAGE_SIZE];
fseeko(mem_fp, region.addr, SEEK_SET);  
for (;current_address < end_address; current_address += PAGE_SIZE) {
        fread(page, 1, PAGE_SIZE, mem_fp);

        int res;
        res = fwrite(page, 1, PAGE_SIZE, dump_fp);
        if (res != PAGE_SIZE) {
            fprintf(stderr, "Error writing to dump file.");
            exit(1);
        }
    }
}

   } 

void read_proc_map_info (char *map_str,mem_region_entry *region)
{
char *start_addr=strtok(map_str,"-");
char *end_addr = strtok(NULL, " ");
char *protection = strtok(NULL, " ");
strtok(NULL, " "); strtok(NULL, " ");
char *inode = strtok(NULL, " ");
char *filename = strtok(NULL, "");

region->addr = strtoull(start_addr, NULL, 16);
region->size = strtoull(end_addr, NULL, 16) - region->addr;
region->inode = atoi(inode);
region->type = 0;
region->protect = 0;
region->filename = filename;
if(*(protection)=='r') {
region->protect |= PROT_READ;
}

if(*(protection + 1)=='w') {
        region->protect |= PROT_WRITE;
    }

if(*(protection + 2) == 'x') {
        region->protect |= PROT_EXEC;
    }

if(*(protection + 3) == 's') {
        region->type |= MAP_SHARED;
    } else {
        region->type |= MAP_PRIVATE;
    }
}

int main(int argc, char **argv)
{
char *dump_path=DUMP_FILE;
pid_t pid=0;
if(argv[1]==NULL)
{
printf("Usage:dumper.c PID\n");
exit(0);
}
pid = atoi(argv[1]);
if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
fprintf(stderr, "Failed to attach to pid: %d\n", pid);
return 1;
}

wait(NULL);

char maps_path[30];
char mem_path[30];

sprintf(maps_path,"/proc/%d/maps",pid);		// read /proc/$pid/maps to see what parts of the process memory are mapped
sprintf(mem_path,"/proc/%d/mem",pid);			// memory mapped contents of the PID

FILE *maps_fp = fopen(maps_path, "r");
if (!maps_fp) {
fprintf(stderr, "Error opening maps file for pid: %d\n", pid);
return 1;
}
FILE *mem_fp = fopen(mem_path, "r");
if (!mem_fp) {
fprintf(stderr, "Error opening mem file for pid: %d\n", pid);
return 1;
}
FILE *dump_fp;
dump_fp = fopen(dump_path, "wb");
if (!dump_fp) {
fprintf(stderr, "Error opening output dump file with path: %s\n", dump_path);
return 1;
}
char *mem_map_str = NULL;
size_t str_size = 0;
while (getline(&mem_map_str, &str_size, maps_fp) != -1) {
mem_region_entry region;
read_proc_map_info(mem_map_str, &region);
dump_mem_region(region, mem_fp, dump_fp);
}
if (mem_map_str){
 free(mem_map_str);
}
fclose(maps_fp);
fclose(mem_fp);
fclose(dump_fp);

ptrace(PTRACE_DETACH, pid, NULL, NULL);
return 0;
}