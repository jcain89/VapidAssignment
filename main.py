import pefile
import sys
import os

# Loading an executable
filepath = sys.argv[1]
targetVirtualAddressParam = sys.argv[2]
targetVirtualAddress = hex(targetVirtualAddressParam)
pe = pefile.PE(str(filepath))



def CheckForValidFilePath():
    isExist = os.path.exists(str(filepath))
    if os.path.exists(filepath):
        return
    raise "This value is not a valid file path, terminating program!"
    exit(1)


def CheckForValidInput(targetVirtualAddressParam):
        hex = int(targetVirtualAddressParam, 16)
        if (hex != True):
            raise ("This value is not a valid hexadecimal number, terminating program!")
            exit(1)
        return


def ConvertTargetVirtualAddressToTargetPointer(filename, targetVirtualAddressParam):
    for section in pe.sections:
        if hex(section.VirtualAddress + section.Misc_VirtualSize < targetVirtualAddress):
            resultSection = section
            break
    offset = hex(targetVirtualAddress - resultSection.VirtualAddress)
    targetFilePointer = resultSection.PointerToRawData + offset
    print("0x" + str(targetVirtualAddress) + "  -> 0x" + str(targetFilePointer))



if __name__ == '__main__':
    CheckForValidFilePath(filepath)
    CheckForValidInput(targetVirtualAddressParam)
    ConvertTargetVirtualAddressToTargetPointer(filepath, targetVirtualAddressParam)
