#!/usr/local/bin/python3

### Author: Jason Brewer
########################
### Purpose: 
### Parse out dlls/exes from a single file or a directory 
### For malware, the IAT contains the most commonly associated Windows Functions (Symbols) related to malware   

import pefile
import argparse
import os
import texttable
import sys
import contextlib
import time
from itertools import combinations
from subprocess import Popen, PIPE

    
class Header(object):

    def __init__(self, name):
        
        try:
            self.name = ''
            self.peFile = pefile.PE(name)
            self.binaryName = ''
            if os.name == 'nt':
                self.binaryName = name.split('\\')[-1]
            elif os.name == 'posix':
                self.binaryName = name.split('/')[-1]
            self.binaryPath = os.path.expanduser(name)
            self.magicNumber = self.peFile.OPTIONAL_HEADER.Magic
        except pefile.PEFormatError as err:
            if err:
                pass
       
        self.Winreference = '[+] https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics'
        self.Extreference = '[+] Description taken from https://www.aldeid.com/wiki/PE-Portable-executable'
        self.delim = "=" * len(self.Winreference)
        
            
    def headerInfo(self):
       
        try:
            peFile = self.peFile
            #if os.name == 'nt':
            binaryName = self.binaryName
            #elif os.name == 'posix':
                #binaryName = self.binaryName
            #print("\n[*] Binary name: %s" % (binaryName))
            print("\n[*] Path to binary: {}".format(self.binaryPath))
            print("[*] Number of Sections: {}".format(peFile.FILE_HEADER.NumberOfSections))
            print("[*] Time Date Stamp : {}".format(peFile.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]))
        except AttributeError as e:
            if e:
                pass
        dirFile = []
        if args.headerFile:
            showVersion = Header(args.headerFile).checkVersion
            showMachineType = Header(args.headerFile).MachineType
            showVersion()
            showMachineType()
                
            # for file in dirFile:
                # path = os.path.join(subdir,file)
                # showMachineType = Header(path).MachineType
            # showMachineType()
                # for file in files:
                    # path = os.path.join(subdir,file)
                    # showMachineType = Header(path).MachineType
                    # showMachineType()
            #showMachineType()
            #for subdir, dirs, files in os.walk(directory):
                # for file in files:
                    # path  = file.split("\\")[-1]
                    # if os.path.isfile(subdir+"\\"+path):
                        # newPath = subdir+"\\"+path
                        # showMachineType = Header(newPath).MachineType
                        # showMachineType()
                

        # Description taken from https://www.aldeid.com/wiki/PE-Portable-executable    
        flags = ['IMAGE_FILE_RELOCS_STRIPPED', 'IMAGE_FILE_EXECUTABLE_IMAGE', 'IMAGE_FILE_LINE_NUMS_STRIPPED', 'IMAGE_FILE_LOCAL_SYMS_STRIPPED', 'IMAGE_FILE_AGGRESSIVE_WS_TRIM', 'IMAGE_FILE_LARGE_ADDRESS_AWARE', '', 'IMAGE_FILE_BYTES_REVERSED_LO', 'IMAGE_FILE_32BIT_MACHINE', 'IMAGE_FILE_DEBUG_STRIPPED', 'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP', 'IMAGE_FILE_NET_RUN_FROM_SWAP', 'IMAGE_FILE_SYSTEM', 'IMAGE_FILE_DLL', 'IMAGE_FILE_UP_SYSTEM_ONLY', 'IMAGE_FILE_BYTES_REVERSED_HI']
        
        intValues_1 = ['0x0001', '0x0002', '0x0004', '0x0008', '0x0010', '0x0020', '0x0040', '0x0080', '0x0100', '0x0200', '0x0400', '0x0800', '0x1000', '0x2000', '0x4000', '0x8000']
        values_1 = [0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000]
        reason = ['Image only, Windows CE, and Windows NT® and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files', 'Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error', 'COFF line numbers have been removed. This flag is deprecated and should be zero', 'COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero', 'Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero', 'Application can handle > 2GB addresses', 'This flag is reserved for future use', 'Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero', 'Machine is based on a 32-bit-word architecture', 'Debugging information is removed from the image file', 'If the image is on removable media, fully load it and copy it to the swap file', 'If the image is on network media, fully load it and copy it to the swap file', 'The image file is a system file, not a user program', 'The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run', 'The file should be run only on a uniprocessor machine', 'Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero']
        
        #delim = "#" * len(self.Winreference)
        #print('\n{}\n{}'.format(delim, self.Extreference))

        # The values are for 32-bit systems
        try:
            if hex(self.magicNumber) == '0x10b':
                if hex(self.peFile.FILE_HEADER.Characteristics)[:3] == '0x2':
                    print("\n[*] File characteristics: {} = 32-bit DLL".format(hex(self.peFile.FILE_HEADER.Characteristics)))
                    print('\n{}'.format(self.Extreference))

                else:
                    print("\n[*] File characteristics: {} = 32-bit Executable".format(hex(self.peFile.FILE_HEADER.Characteristics)))
                    print('\n{}'.format(self.Extreference))

                
                combos(values_1, n=16)
                getMatch(values_1, int(self.peFile.FILE_HEADER.Characteristics), n=16)
                returnExactMatch = getMatch(values_1, int(self.peFile.FILE_HEADER.Characteristics), n=16)

                indexHolder = []
                f = []
                i = []
                r = []

                for inx in returnExactMatch:
                    indexHolder.append(values_1.index(inx))

                for inx in indexHolder:
                    f.append(flags[inx])
                    i.append(intValues_1[inx])
                    r.append(reason[inx])
                
                makeMedTable(f,i,r)
                print('\n{}'.format(self.delim))
            
            # The values for 64-bit systems
            elif hex(self.magicNumber) == '0x20b':
                if len(hex(self.peFile.FILE_HEADER.Characteristics)) == 6:
                    if hex(self.peFile.FILE_HEADER.Characteristics)[:3] == '0x2':
                        print("\n[*] File characteristics: {} = 64-bit DLL".format(hex(self.peFile.FILE_HEADER.Characteristics)))
                        print('\n{}'.format(self.Extreference))

                else:                                
                    print("\n[*] File characteristics: {} = 64-bit Executable".format(hex(self.peFile.FILE_HEADER.Characteristics)))
                    print('\n{}'.format(self.Extreference))

                combos(values_1, n=16)
                getMatch(values_1, int(self.peFile.FILE_HEADER.Characteristics), n=16)
                returnExactMatch = getMatch(values_1, int(self.peFile.FILE_HEADER.Characteristics), n=16)

                indexHolder = []
                f = []
                i = []
                r = []

                for inx in returnExactMatch:
                    indexHolder.append(values_1.index(inx))

                for inx in indexHolder:
                    f.append(flags[inx])
                    i.append(intValues_1[inx])
                    r.append(reason[inx])
                
                makeMedTable(f,i,r)
                print('\n{}'.format(self.delim))
                
        except AttributeError as e:
            if e:
                pass   
                
        return '\n[-----] End of File [-----]'
        
    def MachineType(self):
    
        # From Microsoft Docs
        # The Machine field has one of the following values, which specify the CPU type. 
        # An image file can be run only on the specified machine or on a system that emulates the specified machine.
        try:
            machine = self.peFile.FILE_HEADER.Machine
            fh = "Binary Name : "+self.binaryName + "\n[*] Machine Type: "
        
            mt = '[*] Machine Type Description Taken From Microsoft Docs:\n{}'.format(self.Winreference+'\n')
            # Machine Types from Microsoft Docs
            if hex(machine) == '0x0':
                print("\n{}\n[*] {}: The content of this field is assumed to be applicable to any machine type".format(mt,fh))
            elif hex(machine) == '0x1d3':
                print("\n{}\n[*] {}: Matsushita AM33".format(mt,fh))
            elif hex(machine) == '0x8664':
                print("\n{}\n[*] {}: Is a 64-bit binary and runs on a x64 machine or a system that emulates the specified machine".format(mt,fh))
            elif hex(machine) == '0x1c0':
                print("\n{}\n[*] {}: ARM little endian".format(mt,fh))
            elif hex(machine) == '0xaa64':
                print("\n{}\n[*] {}: ARM64 little endian".format(mt,fh))
            elif hex(machine) == '0x1c4':
                print("\n{}\n[*] {}: ARM Thumb-2 little endian".format(mt,fh))
            elif hex(machine) == '0xebc':
                print("\n{}\n[*] {}: EFI byte code".format(mt,fh))
            elif hex(machine) == '0x14c':
                print("\n{}\n[*] {}: Intel 386 or later processors and compatible processors".format(mt,fh))
            elif hex(machine) == '0x200':
                print("\n{}\n[*] {}: Intel Itanium processor family".format(mt,fh))
            elif hex(machine) == '0x9041':
                print("\n{}\n[*] {}: Mitsubishi M32R little endian".format(mt,fh))
            elif hex(machine) == '0x266':
                print("\n{}\n[*] {} MIPS16".format(mt,fh))
            elif hex(machine) == '0x366':
                print("\n{}\n[*] {}: MIPS with FPU".format(mt,fh))
            elif hex(machine) == '0x466':
                print("\n{}\n[*] {}: MIPS16 with FPU".format(mt,fh))
            elif hex(machine) == '0x1f0':
                print("\n{}\n[*] {}: Power PC little endian".format(mt,fh))
            elif hex(machine) == '0x1f1':
                print("\n{}\n[*] {}: Power PC with floating point support".format(mt,fh))
            elif hex(machine) == '0x166':
                print("\n{}\n[*] {}: MIPS little endian".format(mt,fh))
            elif hex(machine) == '0x5032':
                print("\n{}\n[*] {}: RISC-V 32-bit address space".format(mt,fh))
            elif hex(machine) == '0x5064':
                print("\n{}\n[*] {}: RISC-V 64-bit address space".format(mt,fh))
            elif hex(machine) == '0x5128':
                print("\n{}\n[*] {}: RISC-V 128-bit address space".format(mt,fh))
            elif hex(machine) == '0x1a2':
                print("\n{}\n[*] {}: Hitachi SH3".format(mt,fh))
            elif hex(machine) == '0x1a3':
                print("\n{}\n[*] {}: Hitachi SH3 DSP".format(mt,fh))
            elif hex(machine) == '0x1a6':
                print("\n{}\n[*] {}: Hitachi SH4".format(mt,fh))
            elif hex(machine) == '0x1a8':
                print("\n{}\n[*] {}: Hitachi SH5".format(mt,fh))
            elif hex(machine) == '0x1c2':
                print("\n{}\n{[*] {}: Thumb".format(mt,fh))
            elif hex(machine) == '0x169':
                print("\n{}\n[*] {}: MIPS little-endian WCE v2".format(mt,fh))
        
        except AttributeError as e:
            if e:
                pass
                
        return '\n[-----] End of File [-----]'
          
    def checkVersion(self):

        try:
            print('\n[*] Version Information For: {}\n'.format(self.binaryName))
            if hasattr(self.peFile, 'VS_VERSIONINFO'):
                if hasattr(self.peFile, 'FileInfo'):
                    for entry in self.peFile.FileInfo:      
                        if entry[0]:
                            for str_entry in entry[0].StringTable:
                                for item in str_entry.entries.items():
                                    print('\t{}'.format(str(item).replace("b'", '').replace('(', '').replace(')', '').replace(',',':').replace("'",'')))
        except AttributeError as e:
            if e:
                pass
        return '\n[*] End of Version Information'

class optHeader(Header):

    def __init__(self, name):
    
        self.path = name
        super().__init__(self.path)
        self.name = name
        
        
    def optionalHeaderInfo(self):

        # Printing Some Characteristics of the optional header
        offsetStr = ['0x0', '0x2', '0x3', '0x8', '0xc', '0x10', '0x14', '0x18', '0x20', '0x24', '0x28', '0x2a', '0x2c', '0x2c', '0x2e', '0x30', '0x32', '0x34', '0x38', '0x3c', '0x40', '0x44', '0x46', '0x48', '0x50', '0x58', '0x60', '0x68']
        names = ['Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitalizedData', 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 'Reserved1', 'SizeOfImage', 'SizeOfHeaders', 'Checksum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']
        defs = ['The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable', 'The linker major version number', 'The linker minor version number', 'The size of the code (text) section, or the sum of all code sections if there are multiple sections', 'The size of the initialized data section, or the sum of all such sections if there are multiple data sections', 'The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections', 'The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero', 'The address that is relative to the image base of the beginning-of-code section when it is loaded into memory', 'The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000', 'The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture', 'The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture\'s page size, then FileAlignment must match SectionAlignment', 'The major version number of the required operating system', 'The minor version number of the required operating system', 'The major version number of the image', 'The minor version number of the image', 'The major version number of the subsystem', 'The minor version number of the subsystem', 'Reserved, must be zero', 'The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment', 'The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment', 'The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process', 'The subsystem that is required to run this image', '', 'The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached', 'The size of the stack to commit', 'The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached', 'The size of the local heap space to commit', 'Reserved, must be zero', 'The number of data-directory entries in the remainder of the optional header. Each describes a location and size']
        
        # For PE32 files this field is present; it is not present in PE32+ files 
        offsetInsert = '0x18'
        namesInsert = 'BaseOfData'
        defsInsert = 'The address that is relative to the image base of the beginning of the data section when it is loaded into memory'
        
        # Insert values for a PE32 file not present in PE32+ files
        if hex(self.magicNumber) == '0x10b':
            offsetStr.insert(8,offsetInsert)
            names.insert(8, namesInsert)
            defs.insert(8, defsInsert)
        else:
            pass
  
        # I'm sure there is an easier method to parsing out the size field but this works
        getInfo = []
        for ent in self.peFile.OPTIONAL_HEADER.dump():
            ent = ent.split('\n')
            getInfo.append(ent)

        getData = []
        for i in getInfo[1:]:
            a = str(i).split(':')
            a = str(a).strip('[').strip(']')
            a = str(a).replace(' ','')
            a = str(a).replace("'", '"')
            a = str(a).strip('[').strip(']')
            getData.append(a)

        getLastElement = []
        for i in getData:
            i = i.split(',')
            getLastElement.append(i[-1])
           
        imageSizes = []
        for i in getLastElement:
            i = str(i).strip('"]"')
            imageSizes.append(i)

        # Get longest flag for width in that column/row 
        width = len(max(names, key=len))
        makeLargeTable(offsetStr, imageSizes, names, defs, width)

        return '\n[-----] End of File [-----]'
        
    
    def optionalHeaderDllCharacteristics(self):
        
        try:
            # delim = "#" * len(self.Winreference)
            # print('\n{}\n{}'.format(delim, self.Winreference))
         # Check whether 32-bit or 64-bit
            if hex(self.magicNumber) == '0x10b':
                delim = "#" * len(self.Winreference)
                print('\n{}\n{}'.format(delim, self.Winreference))
                print('\n[*] Binary Name - {} : is a 32-bit binary'.format(self.binaryName))
                print('[*] Optional Header DLL Characteristics: {}\n'.format(hex(self.peFile.OPTIONAL_HEADER.DllCharacteristics)))
                
            elif hex(self.magicNumber) == '0x20b':
                delim = "#" * len(self.Winreference)
                print('\n{}\n{}'.format(delim, self.Winreference))
                print('\n[*] Binary Name - {} : is a 64-bit binary'.format(self.binaryName))
                print('[*] Optional Header DLL Characteristics: {}\n'.format(hex(self.peFile.OPTIONAL_HEADER.DllCharacteristics)))
                
       
        # Dll Characteristics values
            constant = ['', '', '', '', 'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA', 'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE', 'IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY', 'IMAGE_DLLCHARACTERISTICS_NX_COMPAT', 'IMAGE_DLLCHARACTERISTICS_ NO_ISOLATION', 'IMAGE_DLLCHARACTERISTICS_ NO_SEH', 'IMAGE_DLLCHARACTERISTICS_ NO_BIND', 'IMAGE_DLLCHARACTERISTICS_APPCONTAINER', 'IMAGE_DLLCHARACTERISTICS_ WDM_DRIVER', 'IMAGE_DLLCHARACTERISTICS_GUARD_CF', 'IMAGE_DLLCHARACTERISTICS_ TERMINAL_SERVER_AWARE']
            
            value = ['0x0001', '0x0002', '0x0004', '0x0008', '0x0020', '0x0040', '0x0080', '0x0100', '0x0200', '0x0400', '0x0800', '0x1000', '0x2000', '0x4000', '0x8000']
            intValue = [0x0001, 0x0002, 0x0004, 0x0008, 0x0020, 0x0040, 0x0080, 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000]
            
            desc = ['Reserved, must be zero', 'Reserved, must be zero', 'Reserved, must be zero', 'Reserved, must be zero', 'Image can handle a high entropy 64-bit virtual address space', 'DLL can be relocated at load time', 'Code Integrity checks are enforced', 'Image is NX compatible', 'Isolation aware, but do not isolate the image', 'Does not use structured exception (SE) handling. No SE handler may be called in this image', 'Do not bind the image', 'Image must execute in an AppContainer', 'A WDM driver', 'Image supports Control Flow Guard', 'Terminal Server Aware']

            # Iterating over the values and returning only the flags associated with those values
            combos(value, n=15)
            getMatch(intValue, int(self.peFile.OPTIONAL_HEADER.DllCharacteristics), n=15)
            returnExactMatch = getMatch(intValue, int(self.peFile.OPTIONAL_HEADER.DllCharacteristics), n=15)
            
            indexHolder = []
            c = []
            v = []
            d = []
            
            for inx in returnExactMatch:
                indexHolder.append(intValue.index(inx))
                
            for inx in indexHolder:
                c.append(constant[inx])
                v.append(value[inx])
                d.append(desc[inx])
                
            makeMedTable(c,v,d)
            print('\n[*] Windows Subsystem Information\n[*] The following values defined for the Subsystem field of the optional header determine which Windows subsystem (if any) is required to run the image.\n')
        except AttributeError as e:
            if e:
                pass
        return '\n[-----] End of File [-----]'
        
        
    def windowsSubsystem(self):
    
        try:
            # print('\n[*] Windows Subsystem Information\n[*] The following values defined for the Subsystem field of the optional header determine which Windows subsystem (if any) is required to run the image.\n')
       
            constant = ['IMAGE_SUBSYSTEM_UNKNOWN', 'IMAGE_SUBSYSTEM_NATIVE', 'IMAGE_SUBSYSTEM_WINDOWS_GUI', 'IMAGE_SUBSYSTEM_WINDOWS_CUI', 'IMAGE_SUBSYSTEM_OS32_CUI', 'IMAGE_SUBSYSTEM_POSIX_CUI', 'IMAGE_SUBSYSTEM_NATIVE_WINDOWS', 'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', 'IMAGE_SUBSYSTEM_EFI_APPLICATION', 'IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', 'IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', 'IMAGE_SUBSYSTEM_EFI_ROM', 'IMAGE_SUBSYSTEM_XBOX', 'IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION']
            value = ['0', '1','2','3','5', '7', '8', '9', '10', '11', '12', '13', '14','16']
            intValue = [1,2,3,5,7,8,9,10,11,12,13,14,16]
            desc = ['An unknown subsystem', 'Device drivers and native Windows processes', 'The Windows graphical user interface (GUI) subsystem', 'The Windows character subsystem', 'The OS/2 character subsystem', 'The Posix character subsystem', 'Native Win9x driver', 'Windows CE', 'An Extensible Firmware Interface (EFI) application', 'An EFI driver with boot services', 'An EFI driver with run-time services', 'An EFI ROM image', 'XBOX', 'Windows boot application']
            
            subSystem = self.peFile.OPTIONAL_HEADER.Subsystem
            
            combos(subSystem, n=13)
            getMatch(intValue, subSystem, n=13)
            returnExactMatch = getMatch(intValue, subSystem, n=13)
            
            indexHolder = []
            c = []
            v = []
            d = []
            
            for inx in returnExactMatch:
                indexHolder.append(intValue.index(inx))
                
            for inx in indexHolder:
                c.append(constant[inx])
                v.append(value[inx])
                d.append(desc[inx])
                
            makeMedTable(c,v,d)
        except AttributeError as e:
            if e:
                pass
                
        return ''
        

class ImageHeader(object):

    def ImageHeaderAttributes(self):
    
        offset = ['0x00', '0x04', '0x06', '0x08', '0x0c', '0x10', '0x14', '0x16']
        sizes = ['DWORD', 'WORD', 'WORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD']
        memberOf = ['Signature', 'Machine', 'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics']
        defs = ['PE Magic Value', 'GetBackTo', 'Number of Sections', 'The low 32-bits of the number of seconds since EPOCH indicates file creation date', 'The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated', 'The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated', 'The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file', 'The flags that indicate the attributes of the file']
        
        width = len(max(memberOf, key=len))
        makeLargeTable(offset, sizes, memberOf, defs, width)
        
        return '\n[-----] End of File [-----]'

    def OptionalHeaderAttributes(self):
    
        print('\n[+] https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics')
        offset = ['0x18', '0x1A', '0x1B', '0x1C', '0x20', '0x24', '0x28', '0x2C', '0x30', '0x34', '0x38', '0x3C', '0x40', '0x42', '0x44', '0x46', '0x48', '0x4A', '0x4C', '0x50', '0x54', '0x58', '0x5C', '0x5E', '0x60', '0x64', '0x68', '0x6C', '0x70', '0x74']
        sizes = ['WORD', 'BYTE', 'BYTE', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'WORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'WORD', 'WORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD', 'DWORD']
        memberOf = ['Magic', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitalizedData', 'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 'Win32VersionValue', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']
        defs = ['The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file (PE32). 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable', 'The linker major version number', 'The linker minor version number', 'The size of the code (text) section, or the sum of all code sections if there are multiple sections', 'The size of the initialized data section, or the sum of all such sections if there are multiple data sections', 'The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections', 'The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero', 'The address that is relative to the image base of the beginning-of-code section when it is loaded into memory', 'This field does not appear in PE32+. The address that is relative to the image base of the beginning-of-data section when it is loaded into memory', 'The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000', 'The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture', 'The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture\'s page size, then FileAlignment must match SectionAlignment', 'The major version number of the required operating system', 'The minor version number of the required operating system', 'The major version number of the image', 'The minor version number of the image', 'The major version number of the subsystem', 'The minor version number of the subsystem', 'Reserved, must be zero', 'The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment', 'The combined size of an MS‑DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment', 'The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process', 'The subsystem that is required to run this image', 'Use the "-dll" flag', 'The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached', 'The size of the stack to commit', 'The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached', 'The size of the local heap space to commit', 'Reserved, must be zero', 'The number of data-directory entries in the remainder of the optional header. Each describes a location and size; Malware can set an invalid value for this flag to crash the debugger']

        width = len(max(memberOf, key=len))
        makeLargeTable(offset, sizes, memberOf, defs, width)

        return '\n[-----] End of File [-----]'


class sectionHeader(Header):

    def __init__(self, name):
    
        self.path = name
        super().__init__(self.path)
        self.name = name
        
    def returnSectionsHeader(self):
        
        # Return data from sections in Section Header
        print('-'* len('Sections Information:'))
        print('Sections Information: \n')
        print(self.name.split('\\')[-1])
        print('-'* len(self.name.split('\\')[-1]))
        
        for section in self.peFile.sections:
            print(section.Name.decode().rstrip('\x00') + '\n|\n|---- Virtual Size : ' + hex(section.Misc_VirtualSize) + '\n|\n|---- VirtualAddress : ' + hex(section.VirtualAddress) + '\n|\n|---- SizeOfRawData : ' + hex(section.SizeOfRawData) + '\n|\n|---- PointerToRawData : ' + hex(section.PointerToRawData) + '\n|\n|---- Characteristics : ' + hex(section.Characteristics) + '\n')
        
        print('\n[*] Checking Entropy (Randomness) for each section present\n')
        if os.name == 'nt':
            print("\tSections: ", end='')
            print("\tEntropy:\n")
            for sect in self.peFile.sections:
                print("%17s" % (sect.Name).decode('utf-8'), end='')
                print(("\t%5.2f" % sect.get_entropy()))
        elif os.name == 'posix':
            print("\tSections: ", end='')
            print("\tEntropy:\n")
            for sect in self.peFile.sections:
                print("%17s" % (sect.Name).decode('utf-8'), end='')
                print(("\t\t%5.2f" % sect.get_entropy()))
        print('{}'.format(self.delim))
        return '\n[-----] End of File [-----]'
        
# Supresses stdout when writing to a file (-write flag) instead of using a redirect '>' fileName
class SuppressStdout(object):
    
    def __init__(self, suppress=True):
        self.suppress = suppress
        self.sys_stdout_ref = None

    def __enter__(self):
        self.sys_stdout_ref = sys.stdout
        if self.suppress:
            sys.stdout = self
        return sys.stdout

    def __exit__(self, type, value, traceback):
        sys.stdout = self.sys_stdout_ref

    def write(self):
        pass   
  
# These 2 functions handle the suming of values to return the given flags used
def combos(hexList, n):
    return (c for k in range(1, n+1) for c in combinations(hexList, k))

def getMatch(hexList, target, n):
    best = None
    for c in combos(hexList, n):
        v = (abs(target - sum(c)), len(c), c)
        if best is None or v < best:
            best = v
            if v[0] == 0:
                return v[2]
    return best[2] 

# Function that handles reading in a directory of files
def readDir(directory):

    if args.inputDirectory and not args.showSymbols and not args.sections and not args.dll:
        for subdir, dirs, files in os.walk(directory):
            for file in files:
                if os.name == 'nt':
                    winpath  = file.split("\\")[-1]
                    if os.path.isfile(subdir+"\\"+winpath):
                        newPath = subdir+"\\"+winpath
                        getEntry = Header(newPath).headerInfo
                        showversion = Header(newPath).checkVersion
                        showMachineType = Header(newPath).MachineType
                        showversion()
                        showMachineType()
                        getEntry()

                elif os.name == 'posix':
                    pospath = file.split('/')[-1] 
                    if os.path.isfile(subdir+"/"+pospath):
                        newPath = subdir+"/"+pospath
                        getEntry = Header(newPath).headerInfo
                        showversion = Header(newPath).checkVersion
                        showMachineType = Header(newPath).MachineType
                        showversion()
                        showMachineType()
                        getEntry()

            
    elif args.inputDirectory and args.showSymbols and not args.sections and not args.dll:
        for subdir, dirs, files in os.walk(directory):
            for file in files:
                if os.name == 'nt':
                    winpath  = file.split("\\")[-1]
                    if os.path.isfile(subdir+"\\"+winpath):
                        newPath = subdir+"\\"+winpath
                        if newPath.endswith(".dll") or newPath.endswith(".exe") or "dll" in newPath:
                            returnSymbols(newPath)

                elif os.name == 'posix':
                    pospath = file.split("/")[-1]
                    if os.path.isfile(subdir+"/"+pospath):
                        newPath = subdir+"/"+pospath
                        if newPath.endswith(".dll") or newPath.endswith(".exe") or "dll" in newPath:
                            returnSymbols(newPath)
            

    elif args.inputDirectory and args.sections and not args.showSymbols and not args.dll:
        for subdir, dirs, files in os.walk(directory):
                for file in files:
                    if os.name == 'nt':
                        winpath  = file.split("\\")[-1]
                        if os.path.isfile(subdir+"\\"+winpath):
                            newPath = subdir+"\\"+winpath
                            if newPath.endswith(".dll") or newPath.endswith(".exe") or ".exe." in newPath or ".dll." in newPath:
                                if ".exe.config" not in newPath and ".dll.config" not in newPath:
                                    returnSec = sectionHeader(newPath).returnSectionsHeader
                                    returnSec()
                                    
                    elif os.name == 'posix':
                        pospath = file.split("/")[-1]
                        if os.path.isfile(subdir+"/"+pospath):
                            newPath = subdir+"/"+pospath
                            if newPath.endswith(".dll") or newPath.endswith(".exe") or ".exe." in newPath or ".dll." in newPath:
                                if ".exe.config" not in newPath and ".dll.config" not in newPath:
                                    returnSec = sectionHeader(newPath).returnSectionsHeader
                                    returnSec()
       
            
    elif args.inputDirectory and args.dll:
        for subdir, dirs, files in os.walk(directory):
                for file in files:
                    if os.name == 'nt':
                        winpath  = file.split("\\")[-1]
                        if os.path.isfile(subdir+"\\"+winpath):
                            newPath = subdir+"\\"+winpath
                            dlls = optHeader(newPath).optionalHeaderDllCharacteristics
                            winSub = optHeader(newPath).windowsSubsystem
                            dlls()
                            winSub()

                    elif os.name == 'posix':
                        pospath = file.split('/')[-1] 
                        if os.path.isfile(subdir+"/"+pospath):
                            newPath = subdir+"/"+pospath
                            dlls = optHeader(newPath).optionalHeaderDllCharacteristics
                            winSub = optHeader(newPath).windowsSubsystem
                            dlls()
                            winSub()


        # for entry in dirFile:
            # path = os.path.join(directory, entry)
            # dlls = optHeader(path).optionalHeaderDllCharacteristics
            # winSub = optHeader(path).windowsSubsystem
            # dlls()
            # winSub()

    return '\n[-----] End of File [-----]'

# Function that returns any imported and exported symbols
def returnSymbols(getSymbols):

    cwd = os.getcwd()
    path = os.path.join(cwd, getSymbols)
    try:
        peFile = pefile.PE(path)
    except pefile.PEFormatError as e:
        if e:
            pass
    
    winFunc = windowsFunctions()
    foundFunc = set()
    
    if args.showSymbols == 'imported':
    
        try:
            if os.name == 'nt':
                print('\n', path)
                print('\n',path.split('\\')[-1])
                print('-'*75)
            elif os.name == 'posix':
                print('\n', path)
                print('\n',path.split('/')[-1])
                print('-'*75)
            for symbol in peFile.DIRECTORY_ENTRY_IMPORT:
                print(symbol.dll.decode(),'\n')
                print('\t Address', '\t Symbol')
                for imprt in symbol.imports:
                    if imprt.name != None:
                        print('\t', hex(imprt.address), '\t', imprt.name.decode())
                        for func in winFunc:
                            if func in imprt.name.decode():
                                foundFunc.add((symbol.dll.decode(), func))
                    elif imprt.name == None:
                        print('\t', hex(imprt.address), '\t', 'No Import Symbols')
                print('-'*75)
        except AttributeError as e:     
            print("\n[!!!] 'PE' object has no attribute 'DIRECTORY_ENTRY_IMPORT'\n")
            pass
        except UnboundLocalError as err:
            if err:
                pass

        if os.name == 'nt':        
            returnFoundFunc(foundFunc, path.split('\\')[-1])
        elif os.name == 'posix':
            returnFoundFunc(foundFunc, path.split('/')[-1])

    elif args.showSymbols == 'exported':
    
        try:
            print('\n',path.split('\\')[-1])
            print('-'*75)
            print('\t Ordinal Value', '\t Address', '\t Symbol')
            for exprt in peFile.DIRECTORY_ENTRY_EXPORT.symbols:
                if exprt.name != None:
                    print('\t\t',exprt.ordinal, '\t', hex(peFile.OPTIONAL_HEADER.ImageBase + exprt.address), '\t', exprt.name.decode())
                    for func in winFunc:
                            if func in exprt.name.decode():
                                foundFunc.add((symbol.dll.decode(), func))
                elif exprt.name == None:
                    print('\t', 'None', '\t\t', hex(exprt.address), '\t', 'No Export Symbols')
            print('-'*75)
        except AttributeError as e:     
            print("\n[!!!] 'PE' object has no attribute 'DIRECTORY_ENTRY_EXPORT'\n")
            pass
        except UnboundLocalError as err:
            if err:
                pass
        returnFoundFunc(foundFunc, path.split('\\')[-1])

    return '\n[-----] End of File [-----]'
            
# Next 2 Functions creates tables used
def makeLargeTable(offset, sizes, memberOf, defs, width):

    tableSize = len(offset)
    text = texttable.Texttable()
    oset = []
    szs = []
    mems = []
    deffs = []
    for pos in offset:
        oset.append(pos)
    for s in sizes:
        szs.append(s)
    for mem in memberOf:
        mems.append(mem)
    for d in defs:
        deffs.append(d)
    
    for i in range(tableSize):
        text.add_rows([['Offset', 'Size', 'Member', 'Description'], [oset[i], szs[i], mems[i], deffs[i]]])

    text.set_cols_width([18,18,width, 75])    
    txt = text.draw()
    print(txt)


def makeMedTable(flags, values_1, reason):

    getMaxFlag = len(max(flags, key=len))
    getMaxReason = len(max(reason, key=len))
    tableSize = len(flags)
    text = texttable.Texttable()
    
    
    flagHolder = []
    valuesHolder = []
    reasonHolder = []
    
    for f in flags:
        flagHolder.append(f)
    for v in values_1:
        valuesHolder.append(v)
    for r in reason:
        reasonHolder.append(r)
        
    for i in range(tableSize):
        text.add_rows([['Flag', 'Value', 'Description'], [flagHolder[i], valuesHolder[i], reasonHolder[i]]])
        
    if args.dll and getMaxFlag != 0:
        text.set_cols_width([getMaxFlag,18,getMaxReason])
        txt = text.draw()
        print(txt)
    else:
        text.set_cols_width([40,18,100])
        txt = text.draw()
        print(txt)
 

def makeFuncTable(dl, funcs, defs):

    getMaxDLL = len(max(dl, key=len))
    getMaxFunc = len(max(funcs, key=len))
    tableSize = len(funcs)
    text = texttable.Texttable()
    
    dllHolder = []
    defHolder = []
    funcHolder = []
    
    
    for dll in dl:
        dllHolder.append(dll)
    for d in defs:
        defHolder.append(d)
    for f in funcs:
        funcHolder.append(f)
        
    for i in range(tableSize):
        text.add_rows([['DLL','Function', 'Description'], [dllHolder[i], funcHolder[i], defHolder[i]]])
    
    if getMaxFunc <= 8:
        text.set_cols_width([getMaxDLL, 15, 100])    

    else:
        text.set_cols_width([getMaxDLL, getMaxFunc, 100])
    txt = text.draw()
    print(txt)
    print('\n[***] Section End')
    print('#'*75)
    

def windowsFunctions():

    # Functions identified in Practical Malware Analysis as begin interesting
    # and seen most often with malware analysts. To add to the list, just append whatever
    # function you want but you must make sure you also append a description of it in 
    # list found in returnFoundFunc()
    functions = ['Accept', 'AdjustTokenPrivileges', 'AttachThreadInput', 'Bind', 'BitBlt', 'CertOpenSystemStore', 'Connect', 'ConnectNamedPipe', 'ControlService', 'CreateFile', 'CreateFileMapping', 'CreateMutex', 'CreateProcess', 'CreateRemoteThread', 'CreateService', 'CreateToolhelp32Snapshot', 'CryptAcquireContext', 'DeviceIoControl', 'EnableExecuteProtectionSupport', 'EnumProcesses', 'EnumProcessModules', 'FindFirstFile', 'FindNextFile', 'FindResource', 'FindWindow', 'FtpPutFile', 'GetAdaptersInfo', 'GetAsynckeyState', 'GetDC', 'GetForegroundWindow', 'Gethostbyname', 'Gethostname', 'GetKeyState', 'GetModuleFilename', 'GetModuleHandle', 'GetProcAddress', 'GetStartupInfo', 'GetSystemDefaultLangld', 'GetTempPath', 'GetThreadContext', 'GetVersionEx', 'GetWindowsDirectory', 'inet_addr', 'InternetOpen', 'InternetOpenUrl', 'InternetReadFile', 'InternetWriteFile', 'IsNITAdmin', 'IsWoW64Process', 'LdrLoadDll', 'LoadResource', 'LsaEnumerateLogonSessions', 'MapViewOfFile', 'MapVirtualKey', 'Module32First', 'Module32Next', 'NetScheduleJobAdd', 'NetShareEnum', 'NtQueryDirectoryFile', 'NtQueryInformationProcess', 'NtSetInformationProcess', 'OpenMutex', 'OpenProcess', 'OutputDebugString', 'PeekNamedPipe', 'Process32First', 'Process32Next', 'QueueuserAPC', 'ReadProcessMemory', 'Recv', 'RegisterHotKey', 'RegOpenKey', 'ResumeThread', 'RtlCreateRegistryKey', 'RtlWriteRegistryValue', 'SamlConnect', 'SamlGetPrivateData', 'SamQueryInformationUse', 'Send', 'SetFileTime', 'SetThreadContext', 'SetWindowsHookEx', 'SfcTerminateWatcherThread', 'ShellExecute', 'StartServiceCtrlDispatcher', 'SuspendThread', 'System', 'Thread32First', 'Thread32Next', 'Toolhelp32ReadProcessMemory', 'URLDownloadToFile', 'VirtualAllocEx', 'VirtualProtectEx', 'WideCharToMultiByte', 'WinExec', 'WriteProcessMemory', 'WSAStartup']
    return functions


def returnFoundFunc(found, path):

    references = ['[+] https://resources.infosecinstitute.com/topic/windows-functions-in-malware-analysis-cheat-sheet-part-1/', '[+] https://resources.infosecinstitute.com/topic/windows-functions-in-malware-analysis-cheat-sheet-part-2/']
    
    
    # Definitions of each function mentioned in windowsFunctions()
    defs = ['This function is used to listen for incoming connections. This function indicates that the program will listen for incoming connections on a socket. It is mostly used by malware to communicate with their Command and Communication server', 'This function is used to enable or disable specific access privileges. In a process injection attack, this function is used by malware to gain additional permissions', 'This function attaches the input processing from one thread to another so that the second thread receives input events such as keyboard and mouse events. Keyloggers and other spyware use this function', 'This function is used to associate a local address to a socket in order to listen for incoming connections', 'This function is used to copy graphic data from one device to another. Spyware sometimes uses this function to capture screenshots', 'This function is used to access the certificates stored on the local system', 'This function is used to connect to a remote socket. Malware often uses low-level functionality to connect to a command-and-control server. It is mostly used by malware to communicate with their Command and Communication server', 'This function is used to create a server pipe for interprocess communication that will wait for a client pipe to connect. Backdoors and reverse shells sometimes use ConnectNamedPipe to simplify connectivity to a command-and-control server', 'This function is used to start, stop, modify, or send a signal to a running service. If malware is using its own malicious service, code needs to be analyzed that implements the service in order to determine the purpose of the call', 'Creates a new file or opens an existing file', 'This function is used to create a handle to a file mapping that loads a file into memory and makes it accessible via memory addresses. Launchers, loaders, and injectors use this function to read and modify PE files', 'This function creates a mutual exclusion object that can be used by malware to ensure that only a single instance of the malware is running on a system at any given time. Malware often uses fixed names for mutexes, which can be good host-based indicators to detect additional installations of the malware', 'This function creates and launches a new process. If malware creates a new process, new process needs to be analyzed as well', 'This function is used to start a thread in a remote process. Launchers and stealth malware use CreateRemoteThread to inject code into a different process', 'This function is used to create a service that can be started at boot time. Malware uses CreateService for persistence, stealth, or to load kernel drivers', 'This function is used to create a snapshot of processes, heaps, threads, and modules. Malware often uses this function as part of code that iterates through processes or threads', 'This function is often the first function used by malware to initialize the use of Windows encryption', 'This function sends a control message from user space to a device driver. Kernel malware that needs to pass information between user space and kernel space often use this function', 'This function is used to modify the Data Execution Protection (DEP) settings of the host, making it more susceptible to attack', 'This function is used to enumerate through running processes on the system. Malware often enumerates through processes to find a process into which to inject', 'This function is used to enumerate the loaded modules (executables and DLLs) for a given process. Malware enumerates through modules when doing an injection', 'This function is used to search through a directory and enumerate the file system', 'This function is used to search through a directory and enumerate the file system','This function is used to find a resource in an executable or loaded DLL. Malware sometimes uses resources to store strings, configuration information, or other malicious files. If this function is used, then check for an .rsrc section in the malware’s PE header', 'This function is used to search for an open window on the desktop. Sometimes this function is used as an anti-debugging technique to search for OllyDbg windows', 'This function is used to upload a file to remote FTP server', 'This function is used to obtain information about the network adapters on the system. Backdoors sometimes call GetAdaptersInfo in the information-gathering phase to gather information about infected machines. In some cases, it’s used to gather MAC addresses to check for VMware as part of anti-virtual machine techniques', 'This function is used to determine whether a particular key is being pressed. Malware sometimes uses this function to implement a keylogger', 'This function returns a handle to a device context for a window or the whole screen. Spyware that takes screen captures often uses this function', 'This function returns a handle to the window currently in the foreground of the desktop. Keyloggers commonly use this function to determine in which window the user is entering his keystrokes', 'This function is used to perform a DNS lookup on a particular hostname prior to making an IP connection to a remote host. Hostnames that serve as command and- control servers often make good network-based signatures', 'This function is used to retrieve the hostname of the computer. Backdoors sometimes use gethostname in information gathering phase of the victim machine', 'This function is used by keyloggers to obtain the status of a particular key on the keyboard', 'This function returns the filename of a module that is loaded in the current process. Malware can use this function to modify or copy files in the currently running process', 'This function is used to obtain a handle to an already loaded module. Malware may use GetModuleHandle to locate and modify code in a loaded module or to search for a good location to inject code', 'This function is used to retrieve the address of a function in a DLL loaded into memory. This is used to import functions from other DLLs in addition to the functions imported in the PE file header', 'This function is used to retrieve a structure containing details about how the current process was configured to run, such as where the standard handles are directed', 'This function returns the default language settings for the system. These are used by malwares by specifically designed for region-based attacks', 'This function returns the temporary file path. If malware call this function, check whether it reads or writes any files in the temporary file path', 'This function returns the context structure of a given thread. The context for a thread stores all the thread information, such as the register values and current state', 'This function returns information about which version of Windows is currently running. This can be used as part of a victim survey, or to select between different offsets for undocumented structures that have changed between different versions of Windows', 'This function returns the file path to the Windows directory (usually C:Windows). Malware sometimes uses this call to determine into which directory to install additional malicious programs', 'This function converts an IP address string like 127.0.0.1 so that it can be used by functions such as connect. The string specified can sometimes be used as a network-based signature', 'This function initializes the high-level Internet access functions from WinINet, such as InternetOpenUrl and InternetReadFile. Searching for InternetOpen is a good way to find the start of Internet access functionality. One of the parameters to InternetOpen is the User-Agent, which can sometimes make a good network-based signature', 'This function opens a specific URL for a connection using FTP, HTTP, or HTTPS.URLs, if fixed, can often be good network-based signatures', 'This function reads data from a previously opened URL', 'This function writes data to a previously opened URL', 'This function checks if the user has administrator privileges', 'This function is used by a 32-bit process to determine if it is running on a 64-bit operating system', 'This is a low-level function to load a DLL into a process, just like LoadLibrary. Normal programs use LoadLibrary, and the presence of this import may indicate a program that is attempting to be stealthy', 'This function loads a resource from a PE file into memory. Malware sometimes uses resources to store strings, configuration information, or other malicious files', 'This function is used to enumerate through logon sessions on the current system, which can be used as part of a credential stealer', 'This function is used to map a file into memory and makes the contents of the file accessible via memory addresses. Launchers, loaders, and injectors use this function to read and modify PE files. By using MapViewOfFile, the malware can avoid using WriteFile to modify the contents of a file', 'This function is used to translate a virtual-key code into a character value. It is often used by keylogging malware', 'This function is used to enumerate through modules loaded into a process. Injectors use this function to determine where to inject code', 'This function is used to enumerate through modules loaded into a process. Injectors use this function to determine where to inject code', 'This function submits a request for a program to be run at a specified date and time. Malware can use NetScheduleJobAdd to run a different program. This is an important indicator to see the program that is scheduled to run at future time', 'This function is used to enumerate network shares', 'This function returns information about files in a directory. Rootkits commonly hook this function in order to hide files', 'This function is used to return various information about a specified process. This function is sometimes used as an anti-debugging technique because it can return the same information as CheckRemoteDebuggerPresent', 'This function is used to change the privilege level of a program or to bypass Data Execution Prevention (DEP)', 'This function opens a handle to a mutual exclusion object that can be used by malware to ensure that only a single instance of malware is running on a system at any given time. Malware often uses fixed names for mutexes, which can be good host-based indicators', 'This function is used to open a handle to another process running on the system. This handle can be used to read and write to the other process memory or to inject code into the other process', 'This function is used to output a string to a debugger if one is attached. This can be used as an anti-debugging technique', 'This function is used to copy data from a named pipe without removing data from the pipe. This function is popular with reverse shells', 'This function is used to begin enumerating processes from a previous call to CreateToolhelp32Snapshot. Malware often enumerates through processes to find a process into which to inject', 'This function is used to begin enumerating processes from a previous call to CreateToolhelp32Snapshot. Malware often enumerates through processes to find a process into which to inject', 'This function is used to execute code for a different thread. Malware sometimes uses QueueUserAPC to inject code into another process', 'This function is used to read the memory of a remote process', 'This function is used to receive data from a remote machine. Malware often uses this function to receive data from a remote command-and-control server', 'This function is used to register a handler to be notified anytime a user enters a particular key combination (like CTRL-ALT-J), regardless of which window is active when the user presses the key combination. This function is sometimes used by spyware that remains hidden from the user until the key combination is pressed', 'This function is used to open a handle to a registry key for reading and editing. Registry keys are sometimes written as a way for software to achieve persistence on a host. The registry also contains a whole host of operating system and application setting information', 'This function is used to resume a previously suspended thread. ResumeThread is used as part of several injection techniques', 'This function is used to create a registry from kernel-mode code', 'This function is used to write a value to the registry from kernel-mode code', 'This function is used to connect to the Security Account Manager (SAM) in order to make future calls that access credential information. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords', 'This function is used to query the private information about a specific user from the Security Account Manager (SAM) database. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords', 'This function is used to query information about a specific user in the Security Account Manager (SAM) database. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords', 'This function is used to send data to a remote machine. It is often used by malwares to send data to a remote command-and-control server', 'This function is used to modify the creation, access, or last modified time of a file. Malware often uses this function to conceal malicious activity', 'This function is used to modify the context of a given thread. Some injection techniques use SetThreadContext', 'This function is used to set a hook function to be called whenever a certain event is called. Commonly used with keyloggers and spyware, this function also provides an easy way to load a DLL into all GUI processes on the system. This function is sometimes added by the compiler', 'This function is used to disable Windows file protection and modify files that otherwise would be protected', 'This function is used to execute another program', 'This function is used by a service to connect the main thread of the process to the service control manager. Any process that runs as a service must call this function within 30 seconds of startup. Locating this function in malware will tell that the function should be run as a service', 'This function is used to suspend a thread so that it stops running. Malware will sometimes suspend a thread in order to modify it by performing code injection', 'This function is used to run another program provided by some C runtime libraries. On Windows, this function serves as a wrapper function to CreateProcess', 'This function is used to iterate through the threads of a process. Injectors use these functions to find an appropriate thread into which to inject', 'This function is used to iterate through the threads of a process. Injectors use these functions to find an appropriate thread into which to inject', 'This function is used to read the memory of a remote process', 'This function is used to download a file from a web server and save it to disk. This function is popular with downloaders because it implements all the functionality of a downloader in one function call', 'This function is a memory-allocation routine that can allocate memory in a remote process. Malware sometimes uses VirtualAllocEx as part of process injection', 'This function is used to change the protection on a region of memory. Malware may use this function to change a read-only section of memory to an executable', 'This function is used to convert a Unicode string into an ASCII string', 'This function is used to execute another program', 'This function is used to write data to a remote process. Malware uses WriteProcessMemory as part of process injection', 'This function is used to initialize low-level network functionality. Finding calls to WSAStartup can often be an easy way to locate the start of network related functionality']
    
    if len(found) == 0:
        pass
        return -1
        
    else:
        print('\n{0}\n{1}\n[*] Functions commonly encountered by malware analysts with their corresponding DLL:\n'.format(references[0], references[1]))
        lst = [item for f in found for item in f]
        getDll = []
        getFunc = []
        for index, element in enumerate(lst):
            if index % 2 == 0:
                getDll.append(element)
            else:
                getFunc.append(element)
        
        # Create list of windows functions
        winF = windowsFunctions()
        getFc = []
        for wf in winF:
            getFc.append(wf)
        
        # Get index of Windows Functions associated with malware and other uses 
        indexHolder = []
        for f in getFunc:
            indexHolder.append(getFc.index(f))

        # Get index in Windows Functions and Definitions
        gf = []
        gd = []
        for inx in indexHolder:
            gf.append(getFc[inx])
            gd.append(defs[inx])  

        print('[*] {}\n'.format(path))
        
        # Create Table on DLLs, Windows Functions, and Definitions
        makeFuncTable(getDll, gf, gd)
        

# Handles the command line arguments           
def handleArgs():

    if args.headerFile:
        headInfo = Header(args.headerFile).headerInfo 
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(headInfo())
        else:
            headInfo()

    elif args.inputDirectory:
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(readDir(args.inputDirectory))
                    
        else:
            readDir(args.inputDirectory)
                    
    elif args.show_OptionalHeader:
        optInfo = optHeader(args.show_OptionalHeader).optionalHeaderInfo
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(optInfo())        
        else:
            optInfo()
        
    elif args.MachineType:
        arch = Header(args.MachineType).MachineType
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(arch())
        else:
            arch()
        
    elif args.ih:
        iheader = ImageHeader().ImageHeaderAttributes
        iheader()
    
    elif args.oh:
        oheader = ImageHeader().OptionalHeaderAttributes
        oheader()
    
    # For reading a single file/dll
    elif args.inputFile and args.showSymbols == 'imported':
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(returnSymbols(args.inputFile))
        else:
            returnSymbols(args.inputFile)

    elif args.inputFile and args.showSymbols == 'exported':
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(returnSymbols(args.inputFile))
        else:
            returnSymbols(args.inputFile)
        
    # For reading in a directory containing files/dlls
    elif args.inputDirectory and args.showSymbols == 'imported':
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(readDir(args.inputDirectory))
        else:
            readDir(args.inputDirectory)
            
    elif args.inputDirectory and args.showSymbols == 'exported':
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(readDir(args.inputDirectory))
                        
        else:
            readDir(args.inputDirectory)
        
    elif args.sections and args.inputFile:
        returnSec = sectionHeader(args.inputFile).returnSectionsHeader
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(returnSec())
        else:
            returnSec()
        
    elif args.inputDirectory and args.sections:
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    readDir(args.inputDirectory)
        else:
            readDir(args.inputDirectory)
            
    elif args.dll and args.inputFile:
        dll = optHeader(args.inputFile).optionalHeaderDllCharacteristics
        winSub = optHeader(args.inputFile).windowsSubsystem
        if args.outFile:
            with open(os.path.expanduser(args.outFile), 'w') as f:
                with contextlib.redirect_stdout(f):
                    print(dll(),winSub())
        elif args.inputDirectory and args.dll:
            if args.outFile:
                with open(os.path.expanduser(args.outFile), 'w') as f:
                    with contextlib.redirect_stdout(f):
                        print(readDir(args.inputDirectory))
        else:
            dll()
            winSub()
     

def main():        
        
        global args
        args = ''
        parser = argparse.ArgumentParser()
        parser.add_argument('-header', dest='headerFile', help='Show PE Header information on a single file/dll as well as version information')
        parser.add_argument('-optional', dest='show_OptionalHeader', help='Show Optional Header Information')
        parser.add_argument('-dll', action='store_true', help='Use this flag with the "-f" and "-dir" options to show optional header dll characteristics')
        parser.add_argument('-arch', dest='MachineType', help='Display what system architecture the binary is supposed to run on')
        parser.add_argument('-ih', action='store_true', help='Show Image File Header Attributes and Definitions in a table')
        parser.add_argument('-oh', action='store_true', help='Show Optional Header Attributes and Definitions in a table')
        parser.add_argument('-dir', dest='inputDirectory', help='By itself, it displays header information from files/dlls from a directory. Use this flag in combination with -symbols flag or -sections flag to return the expected data.')
        parser.add_argument('-symbols', choices=['imported', 'exported'], dest='showSymbols', help='Use this flag with the -f flag to show symbols on a single file/dll or with the -dir flag to read in a directory containg files/dlls. A table of commonly used symbols for malware, in addition to network connections, reading/writing files, and the like is displayed at the end of the output')
        parser.add_argument('-sections', action='store_true', help='Display the sections: e.g., .text, .data, .rdata, .bss, idata, .edata, .pdata, PAGE*, .reloc, .rsrc')
        parser.add_argument('-f', dest='inputFile', help='Use this flag in combination with the -symbols flag to list imported and exported symbols for single file/dll or use it with -sections to return section information')
        parser.add_argument('-write', dest='outFile', help='Use this flag to write the output of any command without stdout on the screen (Excluding "-ih" and "-oh" flags)')
        args = parser.parse_args()
        
        handleArgs()
        

            
if __name__ == '__main__':
    main()
