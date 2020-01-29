#!/usr/bin/env python

# Serachbin_better
# improved by h8ohmh@github aka Holger Ohmacht
# former version by seqero lacked case insensitive search,
# hexdump and much more

from __future__ import unicode_literals
import os
import re
import signal
import locale
import sys
import binascii
import unicodedata
import string
import getopt
import subprocess
import traceback
from colorama import Fore, Back, Style
#import termcolor
#import numpy

global default_locale
default_locale="de_DE" #TODO

global setdebug
setdebug= False

class searchbin:
    def __init__ (self):
        global setdebug
        """ Class initializer """
        self.bsize= long(8*1024)
        self.default_locale= default_locale
        self.casesensitive= False
        self.contact='h8ohmh@github.com'
        self.current_filepath= ""
        self.debug=setdebug
        self.dump_bytes=256
        self.start= long(0)
        self.end=long(0)
        self.fh= None
        self.current_filehandle= None
        self.fpattern=""
        self.len_pattern=long(0)
        self.logfile=None
        self.logfilepath=""
        self.match=None
        self.maxmatches=long(0)
        self.numbergrouping= False
        self.offset=long(0)
        self.read_size=long(0)
        self.search_filepaths= {}
        self.shellcommand=""
        self.tpattern=""
        self.verbose=0
        self.version=2
        self.re_pattern=None
        self.xpattern=""
        self.read_size=long(0)
        self.cexecstring=""

        if self.debug:
            self.func_name()
            self.print_attr

        signal.signal(signal.SIGINT, signal.SIG_DFL)

        try:
            locale.setlocale(\
                locale.LC_ALL,\
                locale.setlocale(locale.LC_ALL, \
                    str(self.default_locale)))
        except:
            self.exit_error("ERROR: Cannot set locale!")

        return None

    def func_name(self):
        print "\n<"+sys._getframe(1).f_code.co_name+">"

    def __repr__(self):
        if self.debug:
            self.func_name()

        return 'Pair({0.x!r}, {0.y!r})'.format(self)

    def __str__(self):
        if self.debug:
            self.func_name()
        return '({0.x!s}, {0.y!s})'.format(self)

    def print_attr(self):
        if self.debug:
            self.func_name()
        attrs = vars(self)
        print(''.join("\t%s: %s\n" % item for item in attrs.items()))
        return None

    def exit_error(self, msgstr, code= -1, doexit= True):
        if self.debug:
            self.func_name()
        sys.stderr.write( '%.8192s!!!\n' % msgstr )
        # error_codes = {
            # "Xpatterns":
                # "Cannot search for multiple patterns. '-t -x -f'",
            # "0patterns":
                # "No pattern to search for was supplied. '-t -x -f'",
            # "decode":
                # "The pattern string is invalid.\n" + str(option),
            # "bsize":
                # "The buffer size must be at least %s bytes." % str(option),
            # "sizes":
                # "Size parameters (-b -s -e -m) must be in decimal format.",
            # "fpattern":
                # "No pattern file found named: %s" % option,
            # "startend":
                # "The start of search must come before the end.",
            # "openfile":
                # "Failed opening file: %s" % option,
            # "logwrite":
                # "Could not write to the log file: %s" % option,
            # "read":
                # "Failed reading from file: %s" % option,
        # }
        #sys.stderr.write(traceback.format_exc() + "\n")
        # if not self.debug:
            # sys.stderr.write("Version: %s\n" % self.version)
            # sys.stderr.write("Please Report issues to: %s\n" % self.contact)
            # if err: sys.stderr.write("%s\n" % str(err))
        # sys.stderr.write("Error <%s>: %s\n\n" % (code, error_codes[code]))
        if self.debug:
            print '\nState of variables/attributes:\n'
            sb.print_attr() #<debug>

        if doexit:
            sys.exit(code) # Exit under normal operation.
        if __name__ == "__main__":
            sys.exit(code) # Exit under normal operation.
        raise # Raise error on unittest or other execution.

    def print_version(self):
        if self.debug:
            self.func_name()
        print "Searchbin_better V%s" % self.version
        sys.exit(0)

    def print_help(self):
        if self.debug:
            self.func_name()
        """ Function doc """
        #<debug>
        print(u"""Help:
        Arguments:
    -f FILE,
    --file FILE
        File to search in, multiple files arguments are accepted and
        searched after one by on

    -i PATTERNFILEPATH
    --inputfilepattern PATTERNFILEPATH
                        file to read search pattern
                        from PATTERNFILEPATH

    -t PATTERN,
    --textpattern PATTERN
                        a (non-unicode case-insensitive) text string
                        to search for

    -x PATTERN,
    --hexpattern PATTERN
                        a hexidecimal pattern to search for

    -u NUMBYTES,
    --dumpbytes NUMBYTES
                        dump NUMBYTES like 'hexdump -C' around the
                        matching position

    -n,
    --numbergrouping
                        Enable locale defined Numbergrouping of
                        decimal outputs, like 21652 -> 21'652

    -c,
    --casesensitivematch
                        Enable case sensitive text pattern match
                        (default off)

    -X SHELLCOMMANDSTRING,
    --execute SHELLCOMMANDSTRING
                        execute for each match the given shell command
                        (Uppercase X!!!!)

    -b NUM,
    --buffer-size NUM
                        read buffer size (in bytes). default is 8388608
                        (8MB)

    -s NUM,
    --start NUM         starting position in file to begin searching

    -e NUM,
    --end NUM           end search at this position, measuring from
                        beginning of file

    -m NUM,
    --max-matches NUM
                        maximum number of matches to find

    -l FILEPATH,
    --logfile FILEPATH
                        write matched offsets to FILEPATH, instead of
                        standard output

    -v,
    --verbose           verbose, output the number of bytes searched
                        after each buffer read

    -V,
    --version           print version information

    -h,
    --help
                        show help message and exit""")

        return None

    def hex_to_pattern(self,ahex):
        if self.debug:
            self.func_name()
        #<debug>print "hextopattern called"
        ret = []
        self.pattern = ahex
        if ahex[:2] == "0x": # Remove "0x" from start if it exists.
            self.pattern = ahex[2:]
        try:
            ret = [ p for p in self.pattern.split("??") ]
            try:                  # Python 3.
                return [ bytes.fromhex(p) for p in ret ]
            except AttributeError: # Python 2.
                return [ p.decode("hex") for p in ret ]
        except(TypeError, ValueError):
            self.exit_error('ERROR: Wrong Hex pattern: "%s"' % ahex)

    def text_to_pattern(self,text):
        if self.debug:
            print "debug: " + __name__
        """ Converts a text string into a pattern. """
        try:              # Python 3.
            return [ t.encode('utf-8') for t in text.split("?") ]
        except TypeError: # Python 2.
            return [ t for t in text.split("?") ]

    def file_to_pattern(self,fname):
        if self.debug:
            print "debug: " + __name__
        """ Converts a file into a pattern. """
        try:
            with open(fname, "rb") as f:
                return [f.read()]
        except IOError:
            e = sys.exc_info()[1]
            self.exit_error('ERROR: Wrong File pattern: "%s"' % fname)

    def get_args(self):
        """
        Parse all arguments from the command line using ArgumentParser.
        Returns an args object with attributes representing all arguments.
        """
        if self.debug:
            self.func_name()
        #from argparse import ArgumentParser
        try:
            options, remainder \
                = getopt.getopt(
                sys.argv[1:],
                'f:i:x:t:X:m:b:s:e:u:o:l:dvchnV',
                [
                    'file=',
                    'inputpatternfile=',
                    'hexpattern=',
                    'textpattern=',
                    'execute=',
                    'maxmatches=',
                    'buffersize=',
                    'start=',
                    'end=',
                    'dumpbytes=',
                    'outputformat=',
                    'logfile=',
                    'numbergrouping',
                    'debug',
                    'verbose',
                    'help',
                    'version',
                    'casesensitivematch',
                    ])
        except getopt.GetoptError as err:
            #<todo>
            self.print_help
            self.exit_error('\nERROR: Options Error "%s"!!!' \
                % str(err) )

        c=0
        self.fsearch=""
        for opt, arg in options:
            if self.debug:
                print 'debug: opt="%s"' % opt
            if opt[0] == '-':
                aopt= opt[1:]
            if self.debug:
                print 'debug: arg="%s"' % arg
            if aopt in ('f', '-file'):
                self.search_filepaths[c]= arg
                if self.debug:
                    print 'debug: search in file="%.8192s"\n' \
                        % self.search_filepaths[c]
                c+=1
            elif aopt in ('x', '-hexpattern'):
                self.xpattern= arg
                if self.debug:
                    print 'debug: hexpattern="%s"' % self.xpattern
            elif aopt in ('t', '-textpattern'):
                self.tpattern= arg
            elif aopt in ('n', '-numbergrouping'):
                self.numbergrouping= True
            elif aopt in ('c', '-casesensitivematch'):
                self.casesensitive= True
            elif aopt in ('i', '-inputpatternfile'):
                self.fpattern= arg
            elif aopt in ('X', '-execute'):
                self.shellcommand= '%.16384s' % arg
            elif aopt in ('m', '-maxmatches'):
                self.max_matches= long(arg)
            elif aopt in ('b', '-buffersize'):
                self.bsize= long(arg) #<TODO>
            elif aopt in ('s', '-start'):
                self.start= long(arg) if arg >= 0 else 0
            elif aopt in ('e', '-end'):
                self.end= long(arg)
            elif aopt in ('u', '-dumpbytes'):
                self.dump_bytes= long(arg) if arg > 0 else 256
            elif aopt in ('l', '-logfile'):
                self.log= arg
            elif aopt in ('d', '-debug'):
                self.debug= True
            elif aopt in ('v', '-verbose'):
                self.verbose+=1
            elif aopt in ('V', '-version'):
                self.print_version()
            elif aopt in ('h', '-help'):
                self.print_help()
                self.exit_error("", 0)
            else:
                self.exit_error( 'ERROR: none opt arg: "%s"' % arg )
        pass

    def verify_args(self):
        # """
        # Verify that all the parsed args are correct and work well together.
        # Returns the modified args object.
        # """
        #EBUG = ar.debug
        if self.debug:
            print "debug: " + __name__

        #print "a"+str(len(self.tpattern))
        if (( len( self.tpattern ) <= 0 ) and \
            ( len( self.fpattern ) <= 0 ) and \
            ( len( self.xpattern ) <= 0 )):
            self.exit_error("ERROR: Unusable or No patterns!!!")

        if (( len( self.tpattern ) > 0 ) and \
            ( len( self.fpattern ) > 0 ) and \
            ( len( self.xpattern ) > 0 )):
            self.exit_error("ERROR: Too many patterns "\
                + "- only one pattern allowed!!!")

        if( len(self.fpattern) > 0 ):
            self.pattern= self.file_to_pattern(self.fpattern)

        if( len(self.tpattern) > 0 ):
            self.pattern= self.text_to_pattern(self.tpattern)

        if( len( self.xpattern) > 0 ):
            self.pattern = self.hex_to_pattern(self.xpattern)

        print(self.pattern)

        # # Convert all number args from strings into long integers.
        # try:
            # for attr in [ "bsize", "max_matches", "start", "end" ]:
                # if getattr(ar, attr):
                    # setattr(ar, attr, long(getattr(ar, attr)))

        # except ValueError:
            # e = sys.exc_info()[1]
            # _exit_error("sizes", err=e)

        #<TODO>
        # if self.bsize:
            # if ( self.bsize < len( self.pattern ) * 2):
                # self.exit_error('bsize min:',0 )
            # if self.bsize < len("?".join(self.pattern)) * 2:
                # self.exit_error("bsize", len("?".join(self.pattern)) * 2)
        # else:
            # self.bsize = len(b"".join(self.pattern)) * 2
            # self.bsize = max(self.bsize, 2**23) #

        self.start= self.start or 0
        self.end= self.end or 0
        # # End must be after start <todo>
        if self.end and self.start >= self.end:
            self.exit_error( \
                'ERROR: Wrong Start- "%s" and End-position - '+ \
                'given: start=%d, end=%d"' % (self.start & self.end))

        if self.logfilepath:
            try:
                self.logfile = open(logfilepath, "w")
            except IOError:
                error= sys.exc_info()[1]
                self.exit_error( \
                    'ERROR: Can NOT open log file \"%.8192s"!!!!',\
                    self.logfilepath )
        pass

    def filter_non_printable(self,str):
        if self.debug:
            print "debug: " + __name__
        return ''.join(c for c in str \
            if unicodedata.category(c) in printable)

    def isprint(self,c):
        try:
            v=ord(c)
        except:
            v=ord('.')
        if((v < 32) or (v >= 127)):
            return '.'
        else:
            return c

    def parse_execute_string(self, execstring, offset, fh_name):
        #astring="execuiting now: bash echo %o %p %x %f\n\n"
        if self.debug:
            self.func_name()
        ioffset=int(offset)
        sdoffset=locale.format("%i", \
            ioffset,\
            grouping=self.numbergrouping) #<todo>
        execstring= execstring.replace('%o', str(sdoffset))
        execstring= execstring.replace('%p', str(ioffset))
        execstring= execstring.replace('%f', str(fh_name))
        execstring= execstring.replace('%x', "%x" % ioffset )
        return execstring

#example: shell command
#reset; \
#./searchbin_better3.py -x "0011" --file ./bla.txt -X \
#'ssh user@192.168.178.32 "echo \"found at %o\""'

    def print_pass_pos(self,offset):
        if self.debug:
            self.func_name()
        ioffset=int(offset)
        sdoffset=locale.format("%d", \
            ioffset, \
            grouping=self.numbergrouping)   #<todo>
        sxoffset=locale.format("%X", \
            ioffset, \
            grouping=self.numbergrouping)   #<todo>

        fstring="\nPassing offset:\n" + \
            "\tdec:\t%.40s" + \
            "\t(%i)\n" + \
            "\thex:\t0x%s\n"
        print( \
            fstring \
            % \
            (sdoffset, ioffset, sxoffset))

    def print_match_pos(self, mstart, fh_name):
        if self.debug:
            self.func_name()
        offset=int(mstart)
        sdoffset=locale.format("%i", \
            offset, \
            grouping=self.numbergrouping)  #<todo>
        sxoffset=locale.format("%x", \
            offset, \
            grouping=self.numbergrouping)  #<todo>
        fstring="Match at offset:\n" + \
            "\tdec:\t%.40s\t(%i)\n" + \
            "\thex:\t0x%s\n"+ \
            "\tin:\t%s\n"
        print( fstring \
            % ( \
                sdoffset, \
                offset, \
                sxoffset, \
                fh_name \
              ) \
            )

    def search(self):
        if self.debug:
            self.func_name()
        print "###################################\n"

        fh_name= self.current_filehandle
        fh_read= fh_name.read
        fh_seek= fh_name.seek
        self.len_pattern = len(b"?(?i)".join(self.pattern))

        print self.verbose

        print 'Read_size: %d' % self.read_size
        self.re_pattern= [ re.escape(p) for p in self.pattern ]
        self.re_pattern = b".(?i)".join(self.re_pattern)
        print( 'Pattern: "%s"' % self.pattern )
        print( '... as REGEXP-Pattern: "%r"' % self.re_pattern )
        #<debug>self.print_attr()

        if self.casesensitive:
            tcasesensitive= 0
        else:
            tcasesensitive= re.IGNORECASE
        print( 'DEBUG: Case sensitive search: "%s"\n\n' \
            % self.casesensitive )

        regex_search = \
            re.compile(\
                self.re_pattern, \
                re.DOTALL+re.MULTILINE+tcasesensitive).search

        if self.offset > self.end:
            self.offset= 0
        self.offset= self.start
        try:
            if self.offset:
                fh_seek(self.offset)

        except IOError:
            e = sys.exc_info()[1]
            self.exit_error(\
                'ERROR: Can NOT read file "%.8192s"'
                    % self.current_filepath )
        #<debug> print 'self.len_pattern % d' % self.len_pattern

        self.read_size = self.bsize
        try:
            # Get initial buffer amount.
            buffer = fh_read(self.len_pattern + self.read_size )
        except IOError:
            e = sys.exc_info()[1]
            self.exit_error(\
                'ERROR: Can NOT read file "%s", error: "%s"' \
                % ( self.current_filepath, "Unknown" ) )
            return None

        found= 0
        # Search for a match in the buffer.
        # Set match to -1 if no match, else set it to the match
        # position.
        match = regex_search(buffer)
        #print "%s" % match
        c= 0
        match = -1 if match == None else match.start()
        #self.verbose= True
        # Begin main loop for searching through a file.
        while True: # Begin main loop for searching through a file.
            # print 'c:%d rs:%d o:%d e:%d' \
                # % ( c, \
                # self.read_size, \
                # self.offset, \
                # self.end )

            if match == -1: # No match.
                self.offset += self.read_size
                # If end exists and we are beyond end, finish search.
                if self.end != None and self.offset > self.end:
                    return
                # Erase front portion of buffer.
                buffer = buffer[self.read_size:]
                 # Read more into the buffer.
                buffer += fh_read(self.read_size)
                # Search for next match in the buffer.
                match = regex_search(buffer)
                # If there is no match set match to -1, else the matching position.
                match = -1 if match == None else match.start()

                if self.verbose > 2: # Print each loop offset if verbose is on.
                    self.print_pass_pos( self.offset )

            else: # Else- there was a match.
                # If end exists and we are beyond end, finish search.
                if match == -1 and self.offset + match > self.end:
                    return

                if match != None:
                    found= match
                else:
                    found= -1
                # Print matched offset.
                # Print matched offset.
                find_offset = self.offset + found

                self.print_match_pos( find_offset, fh_name )

                # STDOUT.write("Match at offset:\t%-040.32d %-48.48X
                # in  %s\n" % (
                # #STDOUT.write("Match at offset: %14d 0x%12X
                # in  %s\n" % (
                        # find_offset, find_offset, fh_name))
                #print read_size

                #<ump_bytes>dump some bytes of that match
                if self.verbose > 0:
                    printable = set(string.printable)
                    before= self.dump_bytes/2
                    after= before
                    for ppos in range(match-before, match+after, 16):
                        snv=""
                        scv=""
                        if ppos == match:
                            #style= Back.GREEN
                            style="\033[1;32;40m"
                        else:
                            style= Style.RESET_ALL

                        for pipos in range( 0, 16 ):
                            #print "pos: %d %d\n" % ((ppos+pipos), len(buffer))
                            if (ppos+pipos) < len(buffer):
                                c=  buffer[ppos+pipos]
                                snv+= " %02x" % ord(c)
                                scv+= self.isprint(c)

                        aline=(style+'%s: ' % hex(find_offset+ppos)) +snv+'\t'
                        line=aline+"\t"+scv
                        print line

                if (len(self.shellcommand) > 0):
                    cmd= self.parse_execute_string(\
                        self.shellcommand, \
                        self.offset, \
                        fh_name)
                    acmd=str(cmd)
                    print 'Executing shell command: '\
                        '\033[1;33;40m'+acmd+'\033[0;37;40m'
                    #TODO
                    #list_files = subprocess.run(["ls", "-l"])
                    os.system(acmd);
                print
                    #replace_bad(fn, [ "\\", "/", "!", " ", "|", ":" ] +map(chr, range(128, 255) + range(0, 32)))

                    #print " ".join(hex(ord(n)) for n in my_hex)
                if self.maxmatches:
                    self.maxmatches -= 1
                    if self.maxmatches == 0: # If maximum matches are found, then end.
                        print "Found maximum number of matches.\n"
                        return

                # Search for next match in the buffer.
                match = regex_search(buffer, match+1)
                match = -1 if match == None else match.start()

            if len(buffer) <= self.len_pattern: # If finished reading input then end.
                return
        return None

    def autolog(self, message):
        #"Automatically log the current function details."
        import inspect, logging
        if self.debug:
            self.func_name()
        # Get the previous frame in the stack, otherwise it would
        # be this function!!!
        func = inspect.currentframe().f_back.f_code
        # Dump the message + the name of this function to the log.
        logging.debug("%s: %s in %s:%i" % (
            message,
            func.co_name,
            func.co_filename,
            func.co_firstlineno
        ))

    def run(self):
        if self.debug:
            self.func_name()
        self.get_args() # Get commandline arguments.
        if self.debug:
            self.print_attr() #<debug>
        self.verify_args() # Check arguments for sanity, and edit them a bit.
        c= 0
        cmax= len(self.search_filepaths)
        print 'Files to search: %i' % cmax
        if cmax > 0:
            for c in range(cmax):
                current_filepath=self.search_filepaths[c]
                self.current_filepath= current_filepath

                print 'Searching in file: "%.8192s"' \
                    % current_filepath
                try:
                    #<todo parallel>
                    self.current_filehandle= \
                        open(current_filepath, "rb")

                    # get size of file
                    if self.end <= 0:
                        self.end= os.path.getsize(current_filepath)

                except IOError:
                    self.exit_error(
                        'ERROR: Can NOT open search file/dev: '+
                            '"%.8192s"!!!' % current_filepath)
            #self.search(self.current_filepath, self.filehandler)
            self.search()
            self.current_filehandle.close()
            sys.exit(0)
        else:
            self.exit_error("ERROR: No files given!!!")
        return 0

    def initial(self):
        if self.debug:
            print "debug: " + __name__
        #<debug>
        return None

global sb

if __name__ == "__main__":
    global sb
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    sb= searchbin()
    #sb.initial()
    #sb.print_help()#
    sb.run()
    # class sb asb.run()
