#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>

#define RED "\e[1;31m"
#define GREEN "\e[1;32m"
#define BLUE "\e[1;36m"
#define YELLOW "\e[1;33m"
#define PURPLE "\e[1;35m"
#define ITALIC "\e[3m"

int check_magic_bytes(FILE *file){
    unsigned char elf_magic_bytes[4];

    fread(&elf_magic_bytes, sizeof(char), 4, file);

    if(elf_magic_bytes[0] == 0x7F && elf_magic_bytes[1] == 'E' && elf_magic_bytes[2] == 'L' && elf_magic_bytes[3] == 'F'){
        return 1;
    } else{
        return 0;
    }
}


void inject_shellcode(char *shellcode, FILE *file, long int offset){
    size_t shellcode_size = strlen(shellcode) * sizeof(char);
    fseek(file, offset, SEEK_SET);

    size_t num_write = fwrite(shellcode, sizeof(char), strlen(shellcode), file);
    if(num_write < shellcode_size){
        perror(RED "[!] the shellcode was not completely injected at offset\n");
        exit(1);
    } else{
        printf("\n\e[0;48;5;54m    Shellcode injected into ELF..   \e[m\n\e[35m[*]\e[m\e[3m Shellcode size......:\e[m%zu bytes\n\e[35m[*]\e[m\e[3m injected into......:\e[m %ld\n\e[m", shellcode_size, offset);
    }

    fclose(file);
}


int enum_headers(char *shellcode, FILE *file){    
    fseek(file, 0, SEEK_SET);
    Elf64_Ehdr elf_header;
    fread(&elf_header, sizeof(Elf64_Ehdr), 1, file);

    // Get name
    fseek(file, elf_header.e_shoff + elf_header.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
    Elf64_Shdr strings_table;  // string table section header (informations)
    fread(&strings_table, sizeof(Elf64_Shdr), 1, file);

    char *buffer = (char *)malloc(strings_table.sh_size);
    if(buffer == NULL){
        perror(RED "[!] Failed to allocate memory for section names\n");
        return 1;

    } else{
        fseek(file, strings_table.sh_offset, SEEK_SET);
        fread(buffer, sizeof(char), strings_table.sh_size, file);
    }


    fseek(file, elf_header.e_shoff, SEEK_SET);

    printf("%-20s %-20s %-20s\n", "  [SECTION]", "[NUMBERING]", "[OFFSET]");
    for(int i = 0; i < elf_header.e_shnum; i++){
        Elf64_Shdr section_header;
        fread(&section_header, sizeof(Elf64_Shdr), 1, file);

        int flags = 0;

        char *name = buffer + section_header.sh_name;
        if(strncmp(".note", name, 5) == 0){
            printf(PURPLE "   %-20s %-17d %-20ld\n\e[m", name, i, section_header.sh_offset);
        } else if(section_header.sh_flags == SHF_WRITE){
            printf(GREEN "   %-20s %-17d %-20ld\n\e[m", name, i, section_header.sh_offset);
        } else if(section_header.sh_flags == SHF_EXECINSTR){
            printf(YELLOW "   %-20s %-17d %-20ld\n\e[m", name, i, section_header.sh_offset);
        } else if(section_header.sh_flags == SHF_ALLOC){
            printf(BLUE "   %-20s %-17d %-20ld\n\e[m", name, i, section_header.sh_offset);
        } else{

            printf("   %-20s %-17d %-20ld\n", name, i, section_header.sh_offset);        
        }
    }
    printf(PURPLE "\n[.note SECTION]     ");
    printf(GREEN "[WRITE PERMISSION]     ");
    printf(YELLOW "[EXECUTABLE]     ");
    printf(BLUE "[ALLOCATABLE]     \n\n\n");
    free(buffer);

    long int offset;
    printf(GREEN "[?]\e[m Choosen an offset to inject your shellcode:");
    scanf("%ld", &offset);

    inject_shellcode(shellcode, file, offset);

    return 0;
}


int main(int n_args, char *args[]){
    // ./william_afton ELF
    if(n_args > 3 || n_args < 3){
        fprintf(stderr, RED "[!] Please, use: %s ELF < shellcode hex >\n", args[0]);
        return 1;
    } else{
        FILE *file = fopen(args[1], "rb+");

        if(file == NULL){
            fprintf(stderr, RED "[!] File not open..\n\e[m");
            return 1;
        } else{
            int magic_bytes = check_magic_bytes(file);
            if(magic_bytes == 1){
                printf("\n\e[0;48;5;54m                THE PURPLE GUY                  \e[m\n");
                printf(GREEN "\n[+] This file is a valid ELF\n\n\e[m");
                enum_headers(args[2], file);

            } else{
                printf(RED "\n[+] This file is not a valid ELF\n\n");
                return 1;
            }
        }
    }
    
    return 0;
}

                                                // 0xgrah4m
                                                // ELF injection tool
