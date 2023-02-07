#!/usr/bin/env python
import pefile
import sys
import os

# RUN pip3 install pefile before compilation
# Loading an executable


# Function to check if file path is valid, exits if file not valid
def CheckForValidFilePath(filepath):
    check = os.path.exists(filepath)
    if not check:
        print("This value is not a valid file path, terminating program!")
        exit(1)
    return

# function to check if targetVirtualAdress parameter is valid, if not exits with error, if it
# is then return the value as hex so it can be used in conversion function
def CheckForValidInput(targetVirtualAddressParamater) -> str():
    if targetVirtualAddressParamater.startswith("0x"):
        try:
            int(targetVirtualAddressParamater, 16)
        except ValueError:
            print("This value is not a valid hexadecimal number, terminating program!")
            exit(1)
        return targetVirtualAddressParamater
    elif targetVirtualAddressParamater.isdigit():
        targetVirtualAddressParamater = hex(int(targetVirtualAddressParamater))
        return targetVirtualAddressParamater
    else:
        raise ValueError("This value is not a valid hexidecimal number, terminaing program")
        exit(1)


# function to convert target virtual adress to target pointer takes in TVA
# loops through section if target is found set an offset and add that to
# pointerToRawData from that result section to calc targetFilePointer
def ConvertTargetVirtualAddressToTargetPointer(tvaInput):
    for section in pe.sections:
        found = False
        bottom = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
        top = bottom + section.Misc_VirtualSize
        if top > int(tvaInput, 16) > bottom:
            resultSection = section
            found = True
            break
    if not found:   # if flag not set returns "??"
        print((str(tvaInput)).lower() + " -> " + "??")
    else:   # if flag is set returns the target file pointer
        offset = int(tvaInput,16) - resultSection.VirtualAddress - pe.OPTIONAL_HEADER.ImageBase
        targetFilePointer = resultSection.PointerToRawData + offset
        print(str(tvaInput) + " -> " + str(hex(targetFilePointer)))


if __name__ == '__main__':
    # The following two lines are the two arguments which will be fed through the CLI
    filepath = sys.argv[1]
    targetVirtualAddressParam = sys.argv[2]

    CheckForValidFilePath(filepath)
    # Line above will call function to validate filepath input

    targetVirtualAddress = CheckForValidInput(targetVirtualAddressParam)
    # Line above will call function which returns hex TVA parameter used in conversion function

    pe = pefile.PE(str(filepath))
    # Line above creates pe variable to use for portable executable file fields

    ConvertTargetVirtualAddressToTargetPointer(targetVirtualAddress)
    # Line above calls conversion function which will print the TargetFilePointer
