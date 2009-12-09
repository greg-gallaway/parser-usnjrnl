'''
UsnJrnl.py Release 24NOV09

Created on Nov 24, 2009

@author: Seth Nazzaro, Computer Forensic Specialist
email: seth.nazzaro _ navy.mil

This script will parse the entries from the $USNJRNL$J alternate data stream used by NTFS filesystem. 
To use the script, extract the journal using a forensic tool such as EnCase, FTK, or ProDiscover.

This is intended to be cross platform and not memory intensive.

The Windows time/date parsing is adapted from Activestate code (http://code.activestate.com/recipes/303344/)

This script owes thanks from the USNJRNL parser blog entry by Lance Mueller 
	(http://www.forensickb.com/2008/09/enscript-to-parse-usnjrnl.html)

LICENSE: MIT Open Source License (http://opensource.org/licenses/mit-license.php)

'''

import struct, datetime, sys, os, time
from optparse import OptionParser

def main(argv):

    parser = OptionParser()
    parser.add_option("-f", "--infile", dest="infilename", help="input file name")
    parser.add_option("-o", "--outfile", dest="outfilename", help="output file name (no extension)")
#    parser.add_option("-x", "--xml", action="store_true", dest="xml", default=False, help="create XML Output File")
    parser.add_option("-c", "--csv", action="store_true", dest="csv", default=False, help="create Comma-Separated Values Output File")
    parser.add_option("-t", "--tsv", action="store_true", dest="tsv", default=False, help="create Tab-Separated Values  Output File")
#    parser.add_option("-p", "--py", action="store_true", dest="pyout", default=False, help="create text file of Python data")
    parser.add_option("-s", "--std", action="store_true", dest="stdout", default=False, help="write to stdout")

    (options, args) = parser.parse_args()
   
    if options.infilename is None:
        parser.print_help()
        sys.exit(1)
    else:
        infile = options.infilename
    
    # $USNJRNL files can contain a large amount of leading zeros. Create a smaller file that eliminate them.
    it = file(infile, 'rb')

    position = 0
    while (True):
        data = it.read(6553600)
        data = data.lstrip('\x00')
        if len(data) <1:
            position = position +1
        else:
            position = position*6553600 + (6553600 - len(data))
            break
        
    position = it.tell()- len(data)
    it.seek(position)

    #replace main file with working file, then clean up
    ot = file("%s.tmp"%infile,'wb')
    
    while (True):
        data = it.read(655360)
        if len(data) <655359:
            ot.write(data)
            break
        else:
            ot.write(data)
    
    it.close()
    ot.close()
    data = ''
    
    it = file("%s.tmp"%infile,'rb')
    
    #begin parsing file
    parsefile_small(it, options)


def deflag_item(data_tuple):
    #Replaces values where needed for each tuple, returns new
    #If flags do not exits, then return same value
   
    filename = data_tuple[13].replace('\x00', '') #strip the extra hex zeros put in by MS encoding
    version = "%i.%i" % (data_tuple[1], data_tuple[2]) #Combine Major Minor version fields
    dtg = conv_time(data_tuple[6],data_tuple[7])
    try:
        reason = flags[data_tuple[8]]
    except KeyError as ke:
        reason = deflag_long_reason(data_tuple[8])
    try:
        source = flags[data_tuple[9]]
    except KeyError as ke:
        source = deflag_long_reason(data_tuple[9])
    try:
        fileattributes = file_attributes[data_tuple[11]]
    except KeyError as ke:
        fileattributes = deflag_long_fileattr(data_tuple[11])
    token = (data_tuple[0],version)+data_tuple[3:6]+(dtg,reason,source,data_tuple[10],fileattributes,)+data_tuple[11:13]+(filename,)
    return token

def deflag_long_reason(value):
    #In the event that more than one flag is set for a REASON field, this will read through the flags and concatenate the values.
    setflags = []

    keylist = flags.keys()
    for i in keylist:
        if i&value > 0:
            setflags.append(flags[i])
    return " ".join(setflags)

def deflag_long_fileattr(value):
    #In the event that more than one flag is set for a FILE ATTRIBUTE field, this will read through the flags and concatenate the values.
    setflags = []

    keylist = file_attributes.keys()
    for i in keylist:
        if i&value > 0:
            setflags.append(file_attributes[i])
    return " ".join(setflags)


def parsefile_small(it, options):
    # This takes the data in the file and processes each record into a tuple
    #  The tuple is then written to the output file(s) before proceeding to the
    #  next record. The process is very slow but avoids memory errors.

    position_marker = 0
    go = True 
    
    outfile = cfile = xfile = tfile = pfile = None
    if options.outfilename != None:
        outfile = options.outfilename
    else:
        outfile = options.infilename
        
    if options.csv:
        cfile = file('%s.csv' % outfile,'wb')
        cfile.write(",".join(record_header))
        cfile.write('\n')
   
    if options.tsv:
        tfile = file('%s.tsv' % outfile,'wb')
        tfile.write("\t".join(record_header))
        tfile.write('\n')
        
    #if options.xml:
    #    xfile = file('%s.xml' % outfile,'wb')
        #Not supported

    #if options.pyout:
    #    pfile = file('%s.txt' % outfile,'wb')
        #Not implemented

    if options.stdout:
        print "\t".join(record_header)
        
    while (go == True):
        try:
            #Read the record size, read the next record
            sys.stderr.write("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b Offset %s" % position_marker)

            it.seek(position_marker,os.SEEK_SET )
            data = it.read(800)
            recordsize = struct.unpack_from('i', data)[0]
                                    
            if (recordsize <0) :
                go = False          #Invalid data can create an endless loop
            if (recordsize < 60):
                #Note: There are places in the test $USNJRNL$J file where there are gaps between records that are not accounted for by the record size.
                #The gaps are always 0x00 filled. If the record size is zero, move forward until the next non zero byte is found. The largest gap I found was 296 bytes.

                gap_size = len(data.lstrip('\x00'))
                if  gap_size <1:
                    break
                else:
                    position_marker = position_marker + 800- gap_size
                    continue
            
            formatstring = 'ihhqqqlliiiih%dp' % (recordsize - 58)
            it.seek(position_marker)
            data = it.read(recordsize)
            try:
                sdata = struct.unpack_from(formatstring, data)
            except struct.error as se:
                sys.stderr.write ("\nString '%s' cannot parse:  %s  at offset %s \n" % (formatstring , data, position_marker))
                sys.stderr.write ("\nLength of data is %s \n", len(data))
                sdata = struct.unpack_from(formatstring[:14], data)+(data[58:],)
                position_marker = position_marker + recordsize      #Initially forgot this. A struct error would loop forever...
                continue
                

            #convert records entries to more human readable form
            sdata = deflag_item(sdata)
                            
            #Print in appropriate format
            if options.csv:
                cfile.write(",".join(["%s" % (a) for a in sdata]))
                cfile.write('\n')
            if options.tsv:
                tfile.write("\t".join(["%s" % (a) for a in sdata]))
                tfile.write('\n')
            #if options.xml:
            #    True
                #Not supported
            #if options.pyout:
                #pfile.write(sdata)
             #   True
            if options.stdout:
                print "\t".join(["%s" % (a) for a in sdata])
                print '\n'

            sdata = None
            position_marker = position_marker + recordsize
            
        except struct.error, e:
            sys.stderr.write(e.message)
            go = False
            sys.stderr.write( "Struct format error at Tell: %s \n" %it.tell())
            
        except:
            go = False
            print ("Unexpected error:", sys.exc_info()[0])
            raise
   

def conv_time(l,h):
    #NOTE: This section is taken directly from the site http://code.activestate.com/recipes/303344/
    #This converts a 64-bit windows integer specifying the number of 100-nanosecond
    #intervals which have passed since January 1, 1601.
    #This 64-bit value is split into the
    #two 32 bits stored in the structure.
    #
    # Note- this proved to not match the ourput from Encase when parsing the same hex data. Multiple samples identified the
    # difference as a python timedelta value of 13971 or 13972. I selected 13971 to correct.
    
    d=116444736000000000L #Difference between 1601 and 1970
    answer =(((long(h)<<32) + long(l))-d)/10000000
    try:
        return datetime.datetime.utcfromtimestamp(answer-13971).isoformat(' ')
    except:
        return answer

# GLOBAL variables
flags = {0x00:" ",
0x01:"Data in one or more named data streams for the file was overwritten.",
0x02:"The file or directory was added to.",
0x04:"The file or directory was truncated.",
0x10:"Data in one or more named data streams for the file was overwritten.",
0x20:"One or more named data streams for the file were added to.",
0x40:"One or more named data streams for the file was truncated.",
0x100:"The file or directory was created for the first time.",
0x200:"The file or directory was deleted.",
0x400:"The user made a change to the file's or directory's extended attributes.",
0x800:"A change was made in the access rights to the file or directory.",
0x1000:"The file or directory was renamed and the file name in this structure is the previous name.",
0x2000:"The file or directory was renamed and the file name in this structure is the new name.",
0x4000:"A user toggled the FILE_ATTRIBUTE_NOT_CONTENT_INDEXED attribute.",
0x8000:"A user has either changed one or more file or directory attributes or one or more time stamps.",
0x10000:"An NTFS hard link was added to or removed from the file or directory",
0x20000:"The compression state of the file or directory was changed from or to compressed.",
0x40000:"The file or directory was encrypted or decrypted.",
0x80000:"The object identifier of the file or directory was changed.",
0x100000:"The reparse point contained in the file or directory was changed, or a reparse point was added to or deleted from the file or directory.",
0x200000:"A named stream has been added to or removed from the file or a named stream has been renamed.",
0x80000000:"The file or directory was closed."}

file_attributes = {32:'ARCHIVE',2048:'COMPRESSED',64:'DEVICE',16:'DIRECTORY',16383:'ENCRYPTED',2:'HIDDEN',128:'NORMAL',8192:'NOT_CONTENT_INDEXED',
4096:'OFFLINE',1:'READONLY',1024:'REPARSE_POINT',512:'SPARSE_FILE',4:'SYSTEM',256:'TEMPORARY',65536:'VIRTUAL'}
#REM this is taken from http://msdn.microsoft.com/en-us/library/ee332330(VS.85).aspx



record_header = ('Record Size', 'Version', 'MFT Reference', 'Parent MFT Reference', 'Record Offset', 'Timestamp', 'Reason', 'SourceInfo', 'SecurityID', 'FileAttributes', 'Size of filename', 'Offset to filename', 'Filename')
        
if __name__ == '__main__':
    main(sys.argv[1:])
    
