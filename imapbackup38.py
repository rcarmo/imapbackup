#!/usr/bin/env python3 -u

"""IMAP Incremental Backup Script"""
__version__ = "1.4h"
__author__ = "Rui Carmo (http://taoofmac.com)"
__copyright__ = "(C) 2006-2018 Rui Carmo. Code under MIT License.(C)"
__contributors__ = "jwagnerhki, Bob Ippolito, Michael Leonhard, Giuseppe Scrivano <gscrivano@gnu.org>, Ronan Sheth, Brandon Long, Christian Schanz, A. Bovett, Mark Feit, Marco Machicao"

# = Contributors =
# https://github.com/mmachicao: Port impapbackup core use case to python3.8. Mailbox does not support compression.
# http://github.com/markfeit: Allow password to be read from a file
# http://github.com/jwagnerhki: fix for message_id checks
# A. Bovett: Modifications for Thunderbird compatibility and disabling spinner in Windows
#  Christian Schanz: added target directory parameter
# Brandon Long (Gmail team): Reminder to use BODY.PEEK instead of BODY
# Ronan Sheth: hashlib patch (this now requires Python 2.5, although reverting it back is trivial)
# Giuseppe Scrivano: Added support for folders.
# Michael Leonhard: LIST result parsing, SSL support, revamped argument processing,
#                   moved spinner into class, extended recv fix to Windows
# Bob Ippolito: fix for MemoryError on socket recv, http://python.org/sf/1092502
# Rui Carmo: original author, up to v1.2e

# = TODO =
# - Add proper exception handlers to scanFile() and downloadMessages()
# - Migrate mailbox usage from rfc822 module to email module
# - Investigate using the noseek mailbox/email option to improve speed
# - Use the email module to normalize downloaded messages
#   and add missing Message-Id
# - Test parseList() and its descendents on other imapds
# - Add option to download only subscribed folders
# - Add regex option to filter folders
# - Use a single IMAP command to get Message-IDs
# - Use a single IMAP command to fetch the messages
# - Patch Python's ssl module to do proper checking of certificate chain
# - Patch Python's ssl module to raise good exceptions
# - Submit patch of socket._fileobject.read
# - Improve imaplib module with LIST parsing code, submit patch
# DONE:
# v1.4h
# - Add timeout option
# v1.3c
# - Add SSL support
# - Support host:port
# - Cleaned up code using PyLint to identify problems
#   pylint -f html --indent-string="  " --max-line-length=90 imapbackup.py > report.html
import getpass
import os
import gc
import sys
import time
import getopt
import mailbox
import imaplib
import socket
import re
import hashlib

from six import string_types

class SkipFolderException(Exception):
    """Indicates aborting processing of current folder, continue with next folder."""
    pass


class Spinner:
    """Prints out message with cute spinner, indicating progress"""

    def __init__(self, message, nospinner):
        """Spinner constructor"""
        self.glyphs = "|/-\\"
        self.pos = 0
        self.message = message
        self.nospinner = nospinner
        sys.stdout.write(message)
        sys.stdout.flush()
        self.spin()

    def spin(self):
        """Rotate the spinner"""
        if sys.stdin.isatty() and not self.nospinner:
            sys.stdout.write("\r" + self.message + " " + self.glyphs[self.pos])
            sys.stdout.flush()
            self.pos = (self.pos+1) % len(self.glyphs)

    def stop(self):
        """Erase the spinner from the screen"""
        if sys.stdin.isatty() and not self.nospinner:
            sys.stdout.write("\r" + self.message + "  ")
            sys.stdout.write("\r" + self.message)
            sys.stdout.flush()


def pretty_byte_count(num):
    """Converts integer into a human friendly count of bytes, eg: 12.243 MB"""
    if num == 1:
        return "1 byte"
    elif num < 1024:
        return "%s bytes" % num
    elif num < 1048576:
        return "%.2f KB" % (num/1024.0)
    elif num < 1073741824:
        return "%.3f MB" % (num/1048576.0)
    elif num < 1099511627776:
        return "%.3f GB" % (num/1073741824.0)
    else:
        return "%.3f TB" % (num/1099511627776.0)


# Regular expressions for parsing
MSGID_RE = re.compile("^Message\-Id\: (.+)", re.IGNORECASE + re.MULTILINE)
BLANKS_RE = re.compile(r'\s+', re.MULTILINE)

# Constants
UUID = '19AF1258-1AAF-44EF-9D9A-731079D6FAD7'  # Used to generate Message-Ids


def string_from_file(value):
    """
    Read a string from a file or return the string unchanged.

    If the string begins with '@', the remainder of the string
    will be treated as a path to the file to be read.  Precede
    the '@' with a '\' to treat it as a literal.
    """

    assert isinstance(value, string_types)

    if not value or value[0] not in ["\\", "@"]:
        return value

    if value[0] == "\\":
        return value[1:]

    with open(os.path.expanduser(value[1:]), 'r') as content:
        return content.read().strip()


def download_messages(server, filename, messages, config):
    """Download messages from folder and append to mailbox"""

    if config['overwrite'] and os.path.exists(filename):
        print ("Deleting", filename)
        os.remove(filename)
    
    # Open disk file for append in binary mode
    mbox = open(filename, 'ab')

    # the folder has already been selected by scanFolder()

    # nothing to do
    if not len(messages):
        print ("New messages: 0")
        mbox.close()
        return

    spinner = Spinner("Downloading %s new messages to %s" % (len(messages), filename),
                      config['nospinner'])
    total = biggest = 0

    # each new message
    for msg_id in messages.keys():

        # This "From" and the terminating newline below delimit messages
        # in mbox files.  Note that RFC 4155 specifies that the date be
        # in the same format as the output of ctime(3), which is required
        # by ISO C to use English day and month abbreviations.
        buf = "From nobody %s\n" % time.ctime()
        # If this is one of our synthesised Message-IDs, insert it before
        # the other headers
        if UUID in msg_id:
            buf = buf + "Message-Id: %s\n" % msg_id

        # convert to bytes before writing to file of type binary
        buf_bytes=bytes(buf,'utf-8')
        mbox.write(buf_bytes)

        # fetch message
        msg_id_str = str(messages[msg_id])
        typ, data = server.fetch(msg_id_str, "(RFC822)")
        assert('OK' == typ)
        data_bytes = data[0][1]
        text_bytes = data_bytes.strip().replace(b'\r', b'')
        if config['thunderbird']:
            # This avoids Thunderbird mistaking a line starting "From  " as the start
            # of a new message. _Might_ also apply to other mail lients - unknown
            text_bytes = text_bytes.replace(b"\nFrom ", b"\n From ")
        mbox.write(text_bytes)
        mbox.write(b'\n\n')

        size = len(text_bytes)
        biggest = max(size, biggest)
        total += size

        del data
        gc.collect()
        spinner.spin()

    mbox.close()
    spinner.stop()
    print (": %s total, %s for largest message" % (pretty_byte_count(total),
                                                  pretty_byte_count(biggest)))


def scan_file(filename, overwrite, nospinner):
    """Gets IDs of messages in the specified mbox file"""
    # file will be overwritten
    if overwrite:
        return []
    
    # file doesn't exist
    if not os.path.exists(filename):
        print ("File %s: not found" % filename)
        return []

    spinner = Spinner("File %s" % filename, nospinner)

    # open the mailbox file for read
    mbox = mailbox.mbox(filename)

    messages = {}

    # each message
    i = 0
    HEADER_MESSAGE_ID='Message-Id'
    for message in mbox:
        header = ''
        # We assume all messages on disk have message-ids
        try:
            header = "{0}: {1}".format(HEADER_MESSAGE_ID,message.get(HEADER_MESSAGE_ID))
        except KeyError:
            # No message ID was found. Warn the user and move on
            print
            print ("WARNING: Message #%d in %s" % (i, filename),)
            print ("has no {0} header.".format(HEADER_MESSAGE_ID))

        header = BLANKS_RE.sub(' ', header.strip())
        try:
            msg_id = MSGID_RE.match(header).group(1)
            if msg_id not in messages.keys():
                # avoid adding dupes
                messages[msg_id] = msg_id
        except AttributeError:
            # Message-Id was found but could somehow not be parsed by regexp
            # (highly bloody unlikely)
            print
            print ("WARNING: Message #%d in %s" % (i, filename),)
            print ("has a malformed {0} header.".format(HEADER_MESSAGE_ID))
        spinner.spin()
        i = i + 1

    # done
    mbox.close()
    spinner.stop()
    print (": %d messages" % (len(messages.keys())))
    return messages


def scan_folder(server, foldername, nospinner):
    """Gets IDs of messages in the specified folder, returns id:num dict"""
    messages = {}
    spinner = Spinner("Folder %s" % foldername, nospinner)
    try:
        typ, data = server.select(foldername, readonly=True)
        if 'OK' != typ:
            raise SkipFolderException("SELECT failed: %s" % data)
        num_msgs = int(data[0])

        # each message
        for num in range(1, num_msgs+1):
            # Retrieve Message-Id, making sure we don't mark all messages as read
            typ, data = server.fetch(str(num), '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')

            if 'OK' != typ:
                raise SkipFolderException("FETCH %s failed: %s" % (num, data))

            data_str = str(data[0][1],'utf-8') 
            header = data_str.strip()

            # remove newlines inside Message-Id (a dumb Exchange trait)
            header = BLANKS_RE.sub(' ', header)
            try:
                msg_id = MSGID_RE.match(header).group(1)
                if msg_id not in messages.keys():
                    # avoid adding dupes
                    messages[msg_id] = num
            except (IndexError, AttributeError):
                # Some messages may have no Message-Id, so we'll synthesise one
                # (this usually happens with Sent, Drafts and .Mac news)
                typ, data = server.fetch(
                    str(num), '(BODY[HEADER.FIELDS (FROM TO CC DATE SUBJECT)])')
                if 'OK' != typ:
                    raise SkipFolderException(
                        "FETCH %s failed: %s" % (num, data))
                data_str = str(data[0][1], 'utf-8')
                header = data_str.strip()
                header = header.replace('\r\n', '\t').encode('utf-8')
                messages['<' + UUID + '.' +
                         hashlib.sha1(header).hexdigest() + '>'] = num
            spinner.spin()
    finally:
        spinner.stop()
        print (":",)

    # done
    print ("%d messages" % (len(messages.keys())))
    return messages


def parse_paren_list(row):
    """Parses the nested list of attributes at the start of a LIST response"""
    # eat starting paren
    assert(row[0] == '(')
    row = row[1:]

    result = []

    # NOTE: RFC3501 doesn't fully define the format of name attributes
    name_attrib_re = re.compile("^\s*(\\\\[a-zA-Z0-9_]+)\s*")

    # eat name attributes until ending paren
    while row[0] != ')':
        # recurse
        if row[0] == '(':
            paren_list, row = parse_paren_list(row)
            result.append(paren_list)
        # consume name attribute
        else:
            match = name_attrib_re.search(row)
            assert(match is not None)
            name_attrib = row[match.start():match.end()]
            row = row[match.end():]
            name_attrib = name_attrib.strip()
            result.append(name_attrib)

    # eat ending paren
    assert(')' == row[0])
    row = row[1:]

    # done!
    return result, row


def parse_string_list(row):
    """Parses the quoted and unquoted strings at the end of a LIST response"""
    slist = re.compile('\s*(?:"([^"]+)")\s*|\s*(\S+)\s*').split(row)
    return [s for s in slist if s]


def parse_list(row):
    """Parses response of LIST command into a list"""
    row = row.strip()
    print(row)
    paren_list, row = parse_paren_list(row)
    string_list = parse_string_list(row)
    assert(len(string_list) == 2)
    return [paren_list] + string_list


def get_hierarchy_delimiter(server):
    """Queries the imapd for the hierarchy delimiter, eg. '.' in INBOX.Sent"""
    # see RFC 3501 page 39 paragraph 4
    typ, data = server.list('', '')
    assert(typ == 'OK')
    assert(len(data) == 1)

    data_str = str(data[0], 'utf-8')
    lst = parse_list(data_str)  # [attribs, hierarchy delimiter, root name]
    hierarchy_delim = lst[1]
    # NIL if there is no hierarchy
    if 'NIL' == hierarchy_delim:
        hierarchy_delim = '.'
    return hierarchy_delim


def get_names(server, thunderbird, nospinner):
    """Get list of folders, returns [(FolderName,FileName)]"""

    spinner = Spinner("Finding Folders", nospinner)

    # Get hierarchy delimiter
    delim = get_hierarchy_delimiter(server)
    spinner.spin()

    # Get LIST of all folders
    typ, data = server.list()
    assert(typ == 'OK')
    spinner.spin()

    names = []

    # parse each LIST, find folder name
    for row in data:
        row_str = str(row,'utf-8')
        lst = parse_list(row_str)
        foldername = lst[2]
        #suffix = {'none': '', 'gzip': '.gz', 'bzip2': '.bz2'}[compress]
        if thunderbird:
            filename = '.sbd/'.join(foldername.split(delim))
            if filename.startswith("INBOX"):
                filename = filename.replace("INBOX", "Inbox")
        else:
            filename = '.'.join(foldername.split(delim)) + '.mbox'
        # print "\n*** Folder:", foldername # *DEBUG
        # print "***   File:", filename # *DEBUG
        names.append((foldername, filename))

    # done
    spinner.stop()
    print (": %s folders" % (len(names)))
    return names


def print_usage():
    """Prints usage, exits"""
    #     "                                                                               "
    print ("Usage: imapbackup [OPTIONS] -s HOST -u USERNAME [-p PASSWORD]")
    print (" -a --append-to-mboxes         Append new messages to mbox files. (default)")
    print (" -y --yes-overwrite-mboxes     Overwite existing mbox files instead of appending.")
    print (" -f FOLDERS --folders=FOLDERS  Specifify which folders use.  Comma separated list.")
    print (" -e --ssl                      Use SSL.  Port defaults to 993.")
    print (" -k KEY --key=KEY              PEM private key file for SSL.  Specify cert, too.")
    print (" -c CERT --cert=CERT           PEM certificate chain for SSL.  Specify key, too.")
    print ("                               Python's SSL module doesn't check the cert chain.")
    print (" -s HOST --server=HOST         Address of server, port optional, eg. mail.com:143")
    print (" -u USER --user=USER           Username to log into server")
    print (" -p PASS --pass=PASS           Prompts for password if not specified.  If the first")
    print ("                               character is '@', treat the rest as a path to a file")
    print ("                               containing the password.  Leading '\' makes it literal.")
    print (" -t SECS --timeout=SECS        Sets socket timeout to SECS seconds.")
    print (" --thunderbird                 Create Mozilla Thunderbird compatible mailbox")
    print (" --nospinner                   Disable spinner (makes output log-friendly)")
    print ("\nNOTE: mbox files are created in the current working directory.")
    sys.exit(2)


def process_cline():
    """Uses getopt to process command line, returns (config, warnings, errors)"""
    # read command line
    try:
        short_args = "aynzbekt:c:s:u:p:f:"
        long_args = ["append-to-mboxes", "yes-overwrite-mboxes",
                     "ssl", "timeout", "keyfile=", "certfile=", "server=", "user=", "pass=",
                     "folders=", "thunderbird", "nospinner"]
        opts, extraargs = getopt.getopt(sys.argv[1:], short_args, long_args)
    except getopt.GetoptError:
        print_usage()

    warnings = []
    config = {'overwrite': False, 'usessl': False,
              'thunderbird': False, 'nospinner': False}
    errors = []

    # empty command line
    if not len(opts) and not len(extraargs):
        print_usage()

    # process each command line option, save in config
    for option, value in opts:
        if option in ("-a", "--append-to-mboxes"):
            config['overwrite'] = False
        elif option in ("-y", "--yes-overwrite-mboxes"):
            warnings.append("Existing mbox files will be overwritten!")
            config["overwrite"] = True
        elif option in ("-e", "--ssl"):
            config['usessl'] = True
        elif option in ("-k", "--keyfile"):
            config['keyfilename'] = value
        elif option in ("-f", "--folders"):
            config['folders'] = value
        elif option in ("-c", "--certfile"):
            config['certfilename'] = value
        elif option in ("-s", "--server"):
            config['server'] = value
        elif option in ("-u", "--user"):
            config['user'] = value
        elif option in ("-p", "--pass"):
            try:
                config['pass'] = string_from_file(value)
            except Exception as ex:
                errors.append("Can't read password: %s" % (str(ex)))
        elif option in ("-t", "--timeout"):
            config['timeout'] = value
        elif option == "--thunderbird":
            config['thunderbird'] = True
        elif option == "--nospinner":
            config['nospinner'] = True
        else:
            errors.append("Unknown option: " + option)

    # don't ignore extra arguments
    for arg in extraargs:
        errors.append("Unknown argument: " + arg)

    # done processing command line
    return config, warnings, errors


def check_config(config, warnings, errors):
    """Checks the config for consistency, returns (config, warnings, errors)"""
    if 'server' not in config:
        errors.append("No server specified.")
    if 'user' not in config:
        errors.append("No username specified.")
    if ('keyfilename' in config) ^ ('certfilename' in config):
        errors.append("Please specify both key and cert or neither.")
    if 'keyfilename' in config and not config['usessl']:
        errors.append("Key specified without SSL.  Please use -e or --ssl.")
    if 'certfilename' in config and not config['usessl']:
        errors.append(
            "Certificate specified without SSL.  Please use -e or --ssl.")
    if 'server' in config and ':' in config['server']:
        # get host and port strings
        bits = config['server'].split(':', 1)
        config['server'] = bits[0]
        # port specified, convert it to int
        if len(bits) > 1 and len(bits[1]) > 0:
            try:
                port = int(bits[1])
                if port > 65535 or port < 0:
                    raise ValueError
                config['port'] = port
            except ValueError:
                errors.append(
                    "Invalid port.  Port must be an integer between 0 and 65535.")
    if 'timeout' in config:
        try:
            timeout = int(config['timeout'])
            if timeout <= 0:
                raise ValueError
            config['timeout'] = timeout
        except ValueError:
            errors.append(
                "Invalid timeout value.  Must be an integer greater than 0.")
    return config, warnings, errors


def get_config():
    """Gets config from command line and console, returns config"""
    # config = {
    #   'overwrite': True or False
    #   'server': String
    #   'port': Integer
    #   'user': String
    #   'pass': String
    #   'usessl': True or False
    #   'keyfilename': String or None
    #   'certfilename': String or None
    # }

    config, warnings, errors = process_cline()
    config, warnings, errors = check_config(config, warnings, errors)

    # show warnings
    for warning in warnings:
        print ("WARNING:", warning)

    # show errors, exit
    for error in errors:
        print ("ERROR", error)
    if len(errors):
        sys.exit(2)

    # prompt for password, if necessary
    if 'pass' not in config:
        config['pass'] = getpass.getpass()

    # defaults
    if 'port' not in config:
        if config['usessl']:
            config['port'] = 993
        else:
            config['port'] = 143
    if 'timeout' not in config:
        config['timeout'] = 60

    # done!
    return config


def connect_and_login(config):
    """Connects to the server and logs in.  Returns IMAP4 object."""
    try:
        assert(not (('keyfilename' in config) ^ ('certfilename' in config)))
        if config['timeout']:
            socket.setdefaulttimeout(config['timeout'])

        if config['usessl'] and 'keyfilename' in config:
            print ("Connecting to '%s' TCP port %d," % (
                config['server'], config['port']),)
            print ("SSL, key from %s," % (config['keyfilename']),)
            print ("cert from %s " % (config['certfilename']))
            server = imaplib.IMAP4_SSL(config['server'], config['port'],
                                       config['keyfilename'], config['certfilename'])
        elif config['usessl']:
            print ("Connecting to '%s' TCP port %d, SSL" % (
                config['server'], config['port']))
            server = imaplib.IMAP4_SSL(config['server'], config['port'])
        else:
            print ("Connecting to '%s' TCP port %d" % (
                config['server'], config['port']))
            server = imaplib.IMAP4(config['server'], config['port'])

        # speed up interactions on TCP connections using small packets
        server.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        print ("Logging in as '%s'" % (config['user']))
        server.login(config['user'], config['pass'])
    except socket.gaierror as e:
        (err, desc) = e
        print ("ERROR: problem looking up server '%s' (%s %s)" % (
            config['server'], err, desc))
        sys.exit(3)
    except socket.error as e:
        if str(e) == "SSL_CTX_use_PrivateKey_file error":
            print ("ERROR: error reading private key file '%s'" % (
                config['keyfilename']))
        elif str(e) == "SSL_CTX_use_certificate_chain_file error":
            print ("ERROR: error reading certificate chain file '%s'" % (
                config['keyfilename']))
        else:
            print ("ERROR: could not connect to '%s' (%s)" % (
                config['server'], e))

        sys.exit(4)

    return server


def create_folder_structure(names):
    """ Create the folder structure on disk """
    for imap_foldername, filename in sorted(names):
        disk_foldername = os.path.split(filename)[0]
        if disk_foldername:
            try:
                # print "*** mkdir:", disk_foldername  # *DEBUG
                os.mkdir(disk_foldername)
            except OSError as e:
                if e.errno != 17:
                    raise


def main():
    """Main entry point"""
    try:
        config = get_config()
        server = connect_and_login(config)
        names = get_names(server,config['thunderbird'],config['nospinner'])
        if config.get('folders'):
            dirs = list(map(lambda x: x.strip(), config.get('folders').split(',')))
            if config['thunderbird']:
                dirs = [i.replace("Inbox", "INBOX", 1) if i.startswith("Inbox") else i
                        for i in dirs]
            names = list(filter(lambda x: x[0] in dirs, names))

        # for n, name in enumerate(names): # *DEBUG
        #   print n, name # *DEBUG

        create_folder_structure(names)

        for name_pair in names:
            try:
                foldername, filename = name_pair
                fol_messages = scan_folder(
                    server, foldername, config['nospinner'])
                fil_messages = scan_file(filename, config['overwrite'], config['nospinner'])
                new_messages = {}
                for msg_id in fol_messages.keys():
                    if msg_id not in fil_messages:
                        new_messages[msg_id] = fol_messages[msg_id]

                # for f in new_messages:
                #  print "%s : %s" % (f, new_messages[f])

                download_messages(server, filename, new_messages, config)

            except SkipFolderException as e:
                print (e)

        print ("Disconnecting")
        server.logout()
    except socket.error as e:
        print ("ERROR:", e)
        sys.exit(4)
    except imaplib.IMAP4.error as e:
        print ("ERROR:", e)
        sys.exit(5)


# From http://www.pixelbeat.org/talks/python/spinner.py
def cli_exception(typ, value, traceback):
    """Handle CTRL-C by printing newline instead of ugly stack trace"""
    if not issubclass(typ, KeyboardInterrupt):
        sys.__excepthook__(typ, value, traceback)
    else:
        sys.stdout.write("\n")
        sys.stdout.flush()


if sys.stdin.isatty():
    sys.excepthook = cli_exception


# Hideous fix to counteract http://python.org/sf/1092502
# (which should have been fixed ages ago.)
# Also see http://python.org/sf/1441530
def _fixed_socket_read(self, size=-1):
    data = self._rbuf
    if size < 0:
        # Read until EOF
        buffers = []
        if data:
            buffers.append(data)
        self._rbuf = ""
        if self._rbufsize <= 1:
            recv_size = self.default_bufsize
        else:
            recv_size = self._rbufsize
        while True:
            data = self._sock.recv(recv_size)
            if not data:
                break
            buffers.append(data)
        return "".join(buffers)
    else:
        # Read until size bytes or EOF seen, whichever comes first
        buf_len = len(data)
        if buf_len >= size:
            self._rbuf = data[size:]
            return data[:size]
        buffers = []
        if data:
            buffers.append(data)
        self._rbuf = ""
        while True:
            left = size - buf_len
            recv_size = min(self._rbufsize, left)  # the actual fix
            data = self._sock.recv(recv_size)
            if not data:
                break
            buffers.append(data)
            n = len(data)
            if n >= left:
                self._rbuf = data[left:]
                buffers[-1] = data[:left]
                break
            buf_len += n
        return "".join(buffers)

    
if __name__ == '__main__':
    gc.enable()
    main()
