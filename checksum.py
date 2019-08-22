import os
import sys
import fileinput
from shutil import copyfile
from enum import Enum


START_ADDRESS = 0x0000
END_ADDRESS = 0x14ffe

RESERVED_SPACE = 0x0100
RESERVED_SPACE_SIZE = 0x04

CHECKSUM_SIZE = 0x02

# NOTE You need to be aware of reserved spaces as it does not show up in the hex file and the program will simply read
# it as 0xffff instead


class HexFormat(Enum):
    bytes_start = 1
    bytes_end = 3
    address_start = 3
    address_end = 7
    record_start = 7
    record_end = 9
    program_memory_start = 9


class RecordType:
    def __init__(self):
        pass

    @staticmethod
    def record_hash(input_record):
        if(input_record == 0x00):
            return "Data"
        elif(input_record == 0x01):
            return "End Of File"
        elif(input_record == 0x02):
            return "Extended Segment Address"
        elif(input_record == 0x03):
            return "Start Segment Address"
        elif(input_record == 0x04):
            return "Extended Linear Address"
        elif(input_record == 0x05):
            return "Start Linear Address"
        else:
            return "Unknown Record Type"


class HexFileParser:
    def __init__(self):
        pass

    def twos_comp(self, input_value):
        return (input_value ^ 0xffff) + 1

    def output_readable_file(self, input_hex_file):
        # File handling
        file = open(input_hex_file, "r")
        file_output = open("hex_parser.txt", "w+")

        # Tracking variables
        record_holder = RecordType()
        additive_checksum = 0
        address_adding = 0
        end_of_program_memory = False
        reserved_space_flag = False

        for line in file:
            # LSB appears first and is in little endian format

            # The first character is always ":" in an intel hex file
            # The next two characters are the amount of bytes in that file line
            num_bytes = int("0x" + line[HexFormat.bytes_start.value:HexFormat.bytes_end.value], 16)
            address_bytes = int("0x" + str(int(num_bytes/2)), 16)
            address = int(int("0x" + line[HexFormat.address_start.value:HexFormat.address_end.value], 16)/2)
            record = int("0x" + line[HexFormat.record_start.value:HexFormat.record_end.value], 16)
            program_memory = line[HexFormat.program_memory_start.value:HexFormat.program_memory_start.value+(num_bytes*2)]

            # NOTE if bytes == 2 then it is not part of program memory and is a hex file type "command" thus the bytes
            # that are of size 2 can be ignored in terms of program memory. This is because program memory is 3 byte
            # addressable which uses 4 bytes in the .hex file output but only uses the first 3 bytes to account for
            if(num_bytes == 2):
                # Most of these should be the linear record in the intel hex format which will be denoted by it looking
                # like: ":020000040000fa"
                file_output.write("Bytes: " + "0x{:02x}".format(num_bytes) + " Address: " + "0x{:06x}".format(address)
                                  + " " + str(program_memory) + " -- Record: " + record_holder.record_hash(record)
                                  + "\n")

                current_address = address

                # The extended linear address shows how much needs to be added to the next following lines
                if(record == 0x04):
                    address_adding = int((int("0x" + program_memory, 16) << 16) / 2)

            else:
                # Parse through the line we need to start at the end and go backwards since the intel hex file format
                # is in LSB which appears first, it is also in little endian and is 32 bit addressed, but only the first
                # 24 bits are actually used and mean anything
                length_pgmem = len(program_memory)

                i = 0

                while(i < length_pgmem):
                    # We only count up the checksum if we are still reading the program memory portion of the hex file
                    if(end_of_program_memory == False):
                        # additive_checksum += int("0x" + program_memory[i+2:i+4] + program_memory[i:i+2], 16)
                        # additive_checksum += int("0x" + program_memory[i+4:i+6] + "00", 16)

                        # TODO this is the change for not bitwise operating over 8 bits
                        additive_checksum += int("0x" + program_memory[i+2:i+4] + program_memory[i:i+2], 16)
                        additive_checksum += int("0x" + "00" + program_memory[i+4:i+6], 16)

                    i += 8

                current_address = address + address_adding

                file_output.write("Bytes: " + "0x{:02x}".format(num_bytes) + " Address: " +
                                  "0x{:06x}".format(current_address) + " " + str(program_memory) +
                                  " -- Checksum: " + hex(additive_checksum) + "\n")

                # This accounts for the reserved space in the program memory which does not show up in the hex file
                if(current_address + address_bytes == RESERVED_SPACE and reserved_space_flag == False):
                    reserved_space_flag = True
                    reserved_prgmem = ""
                    for i in range(0, int(RESERVED_SPACE_SIZE/2)):
                        # additive_checksum += 0xffff
                        # additive_checksum += 0xff00
                        # reserved_prgmem += "ffffff00"

                        # TODO this is the change for not bitwise operating over 8 bits
                        additive_checksum += 0xffff
                        additive_checksum += 0x00ff
                        reserved_prgmem += "ffff00ff"

                    file_output.write("Bytes: " + "0x{:02x}".format(num_bytes) + " Address: " +
                                      "0x{:06x}".format(current_address+address_bytes) + " " + str(reserved_prgmem) +
                                      " -- Reserved Checksum: " + hex(additive_checksum) + "\n")

            if(current_address+(int(num_bytes/2)) == (END_ADDRESS)):
                # We are at the end of the program memory space
               end_of_program_memory = True

        # File closing
        file.close()
        file_output.close()

    def insert_checksum(self, input_hex_file):
        # Tracking variables
        additive_checksum = 0
        address_adding = 0
        end_of_program_checksum_memory = False
        reserved_space_flag = False

        for line in fileinput.input(input_hex_file, inplace=True):
            # LSB appears first and is in little endian format

            # The first character is always ":" in an intel hex file
            # The next two characters are the amount of bytes in that file line
            num_bytes = int("0x" + line[HexFormat.bytes_start.value:HexFormat.bytes_end.value], 16)
            address_bytes = int("0x" + str(int(num_bytes/2)), 16)
            address = int(int("0x" + line[HexFormat.address_start.value:HexFormat.address_end.value], 16)/2)
            record = int("0x" + line[HexFormat.record_start.value:HexFormat.record_end.value], 16)
            program_memory = line[HexFormat.program_memory_start.value:HexFormat.program_memory_start.value+(num_bytes*2)]

            # NOTE if bytes == 2 then it is not part of program memory and is a hex file type "command" thus the bytes
            # that are of size 2 can be ignored in terms of program memory. This is because program memory is 3 byte
            # addressable which uses 4 bytes in the .hex file output but only uses the first 3 bytes to account for
            if(num_bytes == 2):
                # Most of these should be the linear record in the intel hex format which will be denoted by it looking
                # like: ":020000040000fa"

                current_address = address

                # The extended linear address shows how much needs to be added to the next following lines
                if(record == 0x04):
                    address_adding = int((int("0x" + program_memory, 16) << 16) / 2)

            else:
                # Parse through the line we need to start at the end and go backwards since the intel hex file format
                # is in LSB which appears first, it is also in little endian and is 32 bit addressed, but only the first
                # 24 bits are actually used and mean anything
                length_pgmem = len(program_memory)

                i = 0

                while(i < length_pgmem):
                    # We only count up the checksum if we are still reading the program memory portion of the hex file
                    if(end_of_program_checksum_memory == False):
                        # additive_checksum += int("0x" + program_memory[i+2:i+4] + program_memory[i:i+2], 16)
                        # additive_checksum += int("0x" + program_memory[i+4:i+6] + "00", 16)

                        # TODO this is the change for not bitwise operating over 8 bits
                        additive_checksum += int("0x" + program_memory[i+2:i+4] + program_memory[i:i+2], 16)
                        additive_checksum += int("0x" + "00" + program_memory[i+4:i+6], 16)
                    i += 8

                current_address = address + address_adding

                # This accounts for the reserved space in the program memory which does not show up in the hex file
                if(current_address + address_bytes == RESERVED_SPACE and reserved_space_flag == False):
                    reserved_space_flag = True

                    for i in range(0, int(RESERVED_SPACE_SIZE/2)):
                        # additive_checksum += 0xffff
                        # additive_checksum += 0xff00

                        # TODO this is the change for not bitwise operating over 8 bits
                        additive_checksum += 0xffff
                        additive_checksum += 0x00ff

            if(current_address+(int(num_bytes/2)) == (END_ADDRESS-CHECKSUM_SIZE)):
                # We are at the end of the program memory space
               end_of_program_checksum_memory = True

            if(current_address == (END_ADDRESS-CHECKSUM_SIZE)):
                # We need to insert the checksum in here
                # Get everything before program memory and everything after program memory and update the lines crc
                remainder_checksum = "{:04x}".format(additive_checksum & 0xffff)
                remainder_checksum_rest = ""
                for i in range(0, len(program_memory)-len(remainder_checksum)):
                    remainder_checksum_rest += "0"

                # We just need to insert the line_checksum into the checksum insertion line
                checksum_insertion_line = line[:HexFormat.program_memory_start.value] + remainder_checksum[2:] + \
                                          remainder_checksum[:2] + remainder_checksum_rest

                # Find the checksum of the line to output to the hex file
                line_checksum = 0
                for i in range(1, len(checksum_insertion_line), 2):
                    line_checksum += int("0x" + checksum_insertion_line[i:i+2], 16)

                line_checksum = self.twos_comp(-1*line_checksum)
                checksum_insertion_line += str(hex(line_checksum))[-2:]

                print(checksum_insertion_line+"\n", end="")
            else:
                # Write what the normal line is in the hex file
                print(line, end="")

        print(checksum_insertion_line)
        print("Additive Checksum: ", hex(additive_checksum & 0xffff))


def main():
    # Old Test
    # f1 = "C:\\Users\\garrett.deguchi\\Desktop\\Checksum_\\fabian-monitor\\Mon.X\\dist\\default\\production\\Mon.X.production.hex"
    # f2 = "C:\\Users\\garrett.deguchi\\Desktop\\Checksum_Python\\Mon.X.production.hex"
    # os.remove(f2)
    # copyfile(f1, f2)
    # parser = HexFileParser()
    # cwd = os.getcwd()
    # cwd += "\\Mon.X\\dist\\default\\production\\Mon.X.production.hex"
    #
    # parser.output_readable_file("Mon.X.production.hex")
    # parser.insert_checksum("C:\\Users\\garrett.deguchi\\Desktop\\Checksum_Python\\Mon.X.production.hex")

    # New
    parser = HexFileParser()
    cwd = os.getcwd()
    cwd += "\\dist\\default\\production\\Mon.X.production.hex"
    parser.insert_checksum(cwd)
    
    parser = HexFileParser()
    cwd = os.getcwd()
    cwd += "\\Mon.X.production.hex"
    parser.output_readable_file(cwd)
    


if __name__ == "__main__":
    main()
