#!/usr/bin/env python
import pefile
import sys
import os

#RUN pip3 install pefile before compilation
# Loading an executable
filepath = sys.argv[1]
targetVirtualAddressParam = sys.argv[2]
print(type(targetVirtualAddressParam))

# if targetVirtualAddressParam.startswith("0x"):
#     targetVirtualAddressParam = int(targetVirtualAddressParam,16)
#     print(targetVirtualAddressParam)
# # if targetVirtualAddressParam.isdigit():
# #     print("ISDIGTI")
# #     targetVirtualAddressParam = hex(int(targetVirtualAddressParam))
# #     print(targetVirtualAddressParam, ": HEXED")
# #     targetVirtualAddressParam.removeprefix("0x")
# print(f"{targetVirtualAddressParam=}")
# print(type(targetVirtualAddressParam))


def CheckForValidFilePath(filepath):
    check = os.path.exists(filepath)
    if not check:
        print("This value is not a valid file path, terminating program!")
        exit(1)
    return


def CheckForValidInput(targetVirtualAddressParam_) -> str():
    if targetVirtualAddressParam_.startswith("0x"):
        try:
            int(targetVirtualAddressParam, 16)
        except ValueError:
            print("This value is not a valid hexadecimal number, terminating program!")
            exit(1)
        return targetVirtualAddressParam_
    elif targetVirtualAddressParam_.isdigit():
        targetVirtualAddressParam_ = hex(int(targetVirtualAddressParam_))
        #print(f"{targetVirtualAddressParam_=}")
        return targetVirtualAddressParam_
    else:
        raise ValueError("This value is not a valid hexidecimal number, terminaing program")
        exit(1)
    # if(type(targetVirtualAddressParam)!=int()):
    #     try:
    #         int(targetVirtualAddressParam, 16)
    #         return
    #     except ValueError:
    #         print("This value is not a valid hexadecimal number, terminating program!")
    #         exit(1)


def ConvertTargetVirtualAddressToTargetPointer(filename, targetVirtualAddressParam):
    """print(pe.sections[0])
    print(pe.sections[1])
    print(pe.sections[2])
    print(pe.sections[3])
    print(pe.sections[4])
    print(pe.sections[5])"""


    print("section count: ", pe.sections.__len__())
    for section in pe.sections:
        found = False
        #print(type(section))
        #values in next line are being treated as a string fix this
        #a="0xa"+"0xb1"
        #print(a)
        # print("Virtual Address: ",section.VirtualAddress)
        # print("Virtual Size: ",hex(section.Misc_VirtualSize))
        # print(targetVirtualAddress)
        bottom = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        top = bottom + section.Misc_VirtualSize
        #print(f"{top=}")
        #print(f"{bottom=}")
        #print(type(top))
        #print(type(bottom))
        if top > int(targetVirtualAddress,16) and bottom < int(targetVirtualAddress,16):
            resultSection = section
            #print("BREAKING")
            found = True
            break
    if not found:
        print(str(targetVirtualAddress) + "  -> " + "??")
    else:
        offset = int(targetVirtualAddress,16) - resultSection.VirtualAddress - pe.OPTIONAL_HEADER.ImageBase
        print(type(offset))
        targetFilePointer = resultSection.PointerToRawData + offset
        print(str(targetVirtualAddress) + "  -> " + str(hex(targetFilePointer)))


if __name__ == '__main__':
    filepath = sys.argv[1]
    targetVirtualAddressParam = sys.argv[2]

    # if targetVirtualAddressParam.isdigit():
    #     print("ISDIGTI")
    #     targetVirtualAddressParam = hex(int(targetVirtualAddressParam))
    #     print(targetVirtualAddressParam, ": HEXED")
    #     targetVirtualAddressParam.removeprefix("0x")
    #print(f"{targetVirtualAddressParam=}")
    #print(type(targetVirtualAddressParam))
    CheckForValidFilePath(filepath)
    targetVirtualAddressParam = CheckForValidInput(targetVirtualAddressParam)
    #print("MAIN TVAP:",targetVirtualAddressParam)
    targetVirtualAddress = targetVirtualAddressParam
    pe = pefile.PE(str(filepath))
    ConvertTargetVirtualAddressToTargetPointer(filepath, targetVirtualAddress)
