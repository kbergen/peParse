"""
	This is a limited PE parsing application
	Copyright (C) 2014  Keith Bergen

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

require 'digest'

class PEParse
	def initialize ioStream
		if ioStream.nil?
			return false
		end
		
		#Standard sizes defined
		@WORD = 2
		@DWORD = 4
		@BYTE = 1
		
		@offset = 0
		
		#Structure definitions
		@DosHeader = Struct.new(:e_magic, :e_cblp, :e_cp, :e_crlc, :e_cparhdr, :e_minalloc, :e_maxalloc, :e_ss, :e_sp, :e_csum, :e_ip, :e_cs, :e_lfarlc, :e_ovno, :e_res, :e_oemid, :e_oeminfo, :e_res2, :e_lfanew)
		@NTHeader = Struct.new(:signature, :fileHeader, :optionalHeader)
		@FileHeader = Struct.new(:machine, :numberOfSections, :timeDateStamp, :pointerToSymbolTable, :numberOfSymbols, :sizeOfOptionalHeader, :characteristics)
		@OptionalHeader = Struct.new(:magic, :majorLinkerVersion, :minorLinkerVersion, :sizeOfCode, :sizeOfInitializedData, :sizeOfUninitializedData, :addressOfEntryPoint, :baseOfCode, :baseOfData, :imageBase, :sectionAlignment, :fileAlignment, :majorOperatingSystemVersion, :minorOperatingSystemVersion, :majorImageVersion, :minorImageVersion, :majorSubsystemVersion, :minorSubsystemVersion, :win32VersionValue, :sizeOfImage, :sizeOfHeaders, :checkSum, :subsystem, :dllCharacteristics, :sizeOfStackReserve, :sizeOfStackCommit, :sizeOfHeapReserve, :sizeOfHeapCommit, :loaderFlags, :numberOfRvaAndSizes, :dataDirectory)
		@DataDirectory = Struct.new(:virtualAddress, :size)
		@SectionHeader = Struct.new(:name, :virtualSize, :virtualAddress, :sizeOfRawData, :pointerToRawData, :pointerToRelocations, :pointerToLinenumbers, :numberOfRelocations, :numberOfLinenumbers, :characteristics)
		
		#Place holder for initialized structures
		@dosHdr = nil
		@ntHdr = nil
		@fileHdr = nil
		@optionalHdr = nil
		@sectionHeaderArray = Array.new	#Holds all of the section headers
		
		#File IO stream
		@exe = ioStream
		
		#File hashes
		@file_md5 = nil
		@file_sha1 = nil
		@file_sha256 = nil
	end
	
	def validateFile
		@exe.seek(0, IO::SEEK_END)
		if(@exe.tell < 97)
			puts "File is too small for an EXE"
			return false
		end
		@exe.rewind			#Rewind file after size
		populateDOSHeader	#Populates the DOS Header for validation
		if @dosHdr.e_magic != [0x4d, 0x05a]
			puts "Error: magic byte mismatch. " + arrayToHex(@dosHdr.e_magic).join
			return false
		end
	end
	
	def walkFile
		#Checks file size and MZ header
		validateFile
		
		#Jumps to the PE offset
		skipToPE
		#Populates the rest of the major structures
		populateNTHeader
		#Stores the section header information
		populateSectionHeaders
		
		#Reads the sections into memory.
		#@sectionHeaderArray.each do |header|
		#	readSectionIntoMemory(header.pointerToRawData, header.sizeOfRawData)
		#end
	end
	
	#Skips to PE and starts processing!
	def skipToPE
		offsetToPE = interperateDWORD(@dosHdr.e_lfanew)
		puts "Offset to PE is: "
		puts offsetToPE
		@exe.seek(offsetToPE, IO::SEEK_SET)
		@offset = @exe.tell
	end
	
	def arrayToHex array
		array.collect{|b| b.chr.unpack("H*")}
	end
	
	#Populates the DOS header and subsequently increments the FP counter
	def populateDOSHeader
		@dosHdr = @DosHeader.new
		@dosHdr.e_magic = readData(@WORD, nil)		#Magic
		@dosHdr.e_cblp = readData(@WORD, nil)		#Bytes in last page of file
		@dosHdr.e_cp = readData(@WORD, nil)			#Pages in file
		@dosHdr.e_crlc = readData(@WORD, nil)		#Relocations
		@dosHdr.e_cparhdr = readData(@WORD, nil)	#Size of header in paragraphs
		@dosHdr.e_minalloc = readData(@WORD, nil)	#Min extra paragraphs needed
		@dosHdr.e_maxalloc = readData(@WORD, nil)	#Max extra paragraphs needed
		@dosHdr.e_ss = readData(@WORD, nil)			#Initial (realative) SS value
		@dosHdr.e_sp = readData(@WORD, nil)			#Intial SP value
		@dosHdr.e_csum = readData(@WORD, nil)		#checksum (CRC)
		@dosHdr.e_ip = readData(@WORD, nil)			#Initial IP value
		@dosHdr.e_cs = readData(@WORD, nil)			#Initial (realative) CS value
		@dosHdr.e_lfarlc = readData(@WORD, nil)		#File address of relocation table
		@dosHdr.e_ovno = readData(@WORD, nil)		#Overlay number
		@dosHdr.e_res = readData((@WORD * 4), nil)	#Reserved words
		@dosHdr.e_oemid = readData(@WORD, nil)		#OEM ID
		@dosHdr.e_oeminfo = readData(@WORD, nil)	#OEM info
		@dosHdr.e_res2 = readData( (@WORD * 10), nil)	#Reserved words
		@dosHdr.e_lfanew = readData(@DWORD, nil)	#File address of new exe header
		puts "New Addr is: "
		puts interperateDWORD(@dosHdr.e_lfanew)
	end
	
	def populateNTHeader
		@ntHdr = @NTHeader.new
		@ntHdr.signature = readData(@DWORD, nil)
		@ntHdr.fileHeader = @FileHeader.new
		@ntHdr.optionalHeader = @OptionalHeader.new
		
		#Populate the File Header
		@ntHdr.fileHeader.machine = readData(@WORD, nil)
		@ntHdr.fileHeader.numberOfSections = readData(@WORD, nil)
		@ntHdr.fileHeader.timeDateStamp = readData(@DWORD, nil)
		@ntHdr.fileHeader.pointerToSymbolTable = readData(@DWORD, nil)
		@ntHdr.fileHeader.numberOfSymbols = readData(@DWORD, nil)
		@ntHdr.fileHeader.sizeOfOptionalHeader = readData(@WORD, nil)
		@ntHdr.fileHeader.characteristics = readData(@WORD, nil)
		
		#Populate the OptionalHeader
		@ntHdr.optionalHeader.magic = readData(@WORD, nil)
		@ntHdr.optionalHeader.majorLinkerVersion = readData(@BYTE, nil)
		@ntHdr.optionalHeader.minorLinkerVersion = readData(@BYTE, nil)
		@ntHdr.optionalHeader.sizeOfCode = readData(@DWORD, nil)
		@ntHdr.optionalHeader.sizeOfInitializedData = readData(@DWORD, nil)
		@ntHdr.optionalHeader.sizeOfUninitializedData = readData(@DWORD, nil)
		@ntHdr.optionalHeader.addressOfEntryPoint = readData(@DWORD, nil)
		@ntHdr.optionalHeader.baseOfCode = readData(@DWORD, nil)
		@ntHdr.optionalHeader.baseOfData = readData(@DWORD, nil)
		@ntHdr.optionalHeader.imageBase = readData(@DWORD, nil)
		@ntHdr.optionalHeader.sectionAlignment = readData(@DWORD, nil)
		@ntHdr.optionalHeader.fileAlignment = readData(@DWORD, nil)
		@ntHdr.optionalHeader.majorOperatingSystemVersion = readData(@WORD, nil)
		@ntHdr.optionalHeader.minorOperatingSystemVersion = readData(@WORD, nil)
		@ntHdr.optionalHeader.majorImageVersion = readData(@WORD, nil)
		@ntHdr.optionalHeader.minorImageVersion = readData(@WORD, nil)
		@ntHdr.optionalHeader.majorSubsystemVersion = readData(@WORD, nil)
		@ntHdr.optionalHeader.minorSubsystemVersion = readData(@WORD, nil)
		@ntHdr.optionalHeader.win32VersionValue = readData(@DWORD, nil)
		@ntHdr.optionalHeader.sizeOfImage = readData(@DWORD, nil)
		@ntHdr.optionalHeader.sizeOfHeaders = readData(@DWORD, nil)
		@ntHdr.optionalHeader.checkSum = readData(@DWORD, nil)
		@ntHdr.optionalHeader.subsystem = readData(@WORD, nil)
		@ntHdr.optionalHeader.dllCharacteristics = readData(@WORD, nil)
		@ntHdr.optionalHeader.sizeOfStackReserve = readData(@DWORD, nil)
		@ntHdr.optionalHeader.sizeOfStackCommit = readData(@DWORD, nil)
		@ntHdr.optionalHeader.sizeOfHeapReserve = readData(@DWORD, nil)
		@ntHdr.optionalHeader.sizeOfHeapCommit = readData(@DWORD, nil)
		@ntHdr.optionalHeader.loaderFlags = readData(@DWORD, nil)
		@ntHdr.optionalHeader.numberOfRvaAndSizes = readData(@DWORD, nil)
		
		#Pushes as many IMAGE_DATA_DIRECTORY's as noted by numberOfRvaAndSizes
		@ntHdr.optionalHeader.dataDirectory = Array.new
		nuberOfSections = interperateDWORD(@ntHdr.optionalHeader.numberOfRvaAndSizes)
		(1..nuberOfSections).each do |dir|
			@ntHdr.optionalHeader.dataDirectory.push (@DataDirectory.new(readData(@DWORD, nil), readData(@DWORD, nil)))
		end
		
		# Debug prints to validate data
		puts "PE HDR!"
		puts @ntHdr.signature
		puts "Flile alignment:"
		puts interperateDWORD(@ntHdr.optionalHeader.fileAlignment)
		puts "Number of optional headers"
		puts @ntHdr.optionalHeader.numberOfRvaAndSizes
		puts "Data dirs..."
		@ntHdr.optionalHeader.dataDirectory.each do |dd|
			puts "Virt address"
			puts interperateDWORD dd.virtualAddress
			puts "Size"
			puts interperateDWORD dd.size
		end
		
		
		# Sanity check: Is our current position != size of optional header
		# YET TO IMPLEMENT!
	end
	
	def populateSectionHeaders
		puts "In populateSectionHeaders"
		#Number of sections is defined in @ntHdr.fileHeader.numberOfSections
		numberOfSections = interperateDWORD(@ntHdr.fileHeader.numberOfSections)
		puts "There are #{numberOfSections} sections"
		(1..numberOfSections).each do |section|
			@sectionHeaderArray.push populateSectionHeader
		end
	end
	
	#Populates A section header, returns a @SectionHeader structure. 
	#This should be used in a loop
	def populateSectionHeader
		sh = @SectionHeader.new
		sh.name = readData( (@DWORD * 2), nil)
		sh.virtualSize = readData(@DWORD, nil)
		sh.virtualAddress = readData(@DWORD, nil)
		sh.sizeOfRawData = readData(@DWORD, nil)
		sh.pointerToRawData = readData(@DWORD, nil)
		sh.pointerToRelocations = readData(@DWORD, nil)
		sh.pointerToLinenumbers = readData(@DWORD, nil)
		sh.numberOfRelocations = readData(@WORD, nil)
		sh.numberOfLinenumbers = readData(@WORD, nil)
		sh.characteristics = readData(@DWORD, nil)
		
		#DEBUG!
		puts sh.name.collect{|b| b.chr}.join
		#End of debug
		
		return sh
	end
	
	def readSectionIntoMemory offsetInFile, sizeOfSection
		return readData(sizeOfSection, offsetInFile)
	end
	
	#Bytes is required, offset can be nil, it assumes its at the last read pointer
	def readData bytes, offset
		if offset.nil?
			offset = @offset	# if no offset is given assume its the last read pointer
		end
		buffer = Array.new
		buffer = IO.read(@exe, bytes, offset).split("").collect{|x| x.ord}
		@offset += bytes	#Keeps count of your offset
		return buffer
	end
	
	#Pulls data from array, limited to 4 bytes (entries), and reverses their order
	#Then it passes that to another function to convert it to a number
	def interperateDWORD array
		#array.reverse.collect{|b| b.chr.unpack("H*")}.join.ord
		return arrrayToInteger(array[0..3].reverse)
	end
	
	#Takes the array and converts it to an integer.
	#Input is an array of data. Converts it to char values so that unpack can
	#be applied to it. Then it joins it and converts it to an integer, EXPECTING
	#base16 (HEX) as its input.
	def arrrayToInteger array
		return array.collect{|b| b.chr.unpack("H*")}.join.to_i(16)
	end
	
	#TEST FUNCTION
	def testDosHeader
		populateDOSHeader
		puts interperateDWORD(@dosHdr.e_lfanew)
	end
	
	#Takes an array as input
	def hash_sha256 input
		hash = Digest::SHA256.new
		input.each do |byte|
			hash.update byte
		end
		return hash.hexdigest
	end
	
	#Takes an array as input
	def hash_sah1 input
		hash = Digest::SHA1
		input.each do |byte|
			hash.update byte
		end
		return hash.hexdigest
	end
	
	#Takes an array as input
	def md5 input
		hash = Digest::MD5
		input.each do |byte|
			hash.update byte
		end
		return hash.hexdigest
	end
	
	#Hashes the entire file
	def hashFile
		@file_md5 = Digest::MD5.hexdigest @exe.read
		@exe.rewind
		@file_sha1 = Digest::SHA1.hexdigest @exe.read
		@exe.rewind
		@file_sha256 = Digest::SHA256.hexdigest @exe.read
		@exe.rewind
	end
	
	#Returns a structure containing the hashes of the file
	# THIS MUST BE RUN AFTER hashFiless
	def returnFileHashes
		fileHash = Struct.new(:md5, :sha1, :sha256)
		fs = fileHash.new
		fs.md5 = @file_md5
		fs.sha1 = @file_sha1
		fs.sha256 = @file_sha256
		
		return fs
	end
end

#Just in testing phases
def main
	fileHash = Struct.new(:md5, :sha1, :sha256)
	fs = fileHash.new
	
	#Initialize the PE parser
	pe = PEParse.new(File.open(ARGV[0], "rb"))
	
	#Hash the file
	pe.hashFile
	
	#Returns a struct of the hashes
	fs = pe.returnFileHashes
	
	#Print crap out!
	puts fs.md5
	puts fs.sha1
	puts fs.sha256
	
	#Walk the file
	pe.walkFile
end

main