#!/usr/bin/env python3 -u

"""IMAP Incremental Backup Script"""
__version__ = "1.4h"
__author__ = "Rui Carmo (http://taoofmac.com)"
__copyright__ = "(C) 2006-2018 Rui Carmo. Code under MIT License.(C)"
__contributors__ = """jwagnerhki, Bob Ippolito, Michael Leonhard,
 Giuseppe Scrivano <gscrivano@gnu.org>, Ronan Sheth, Brandon Long,
 Christian Schanz, A. Bovett, Mark Feit, Marco Machicao"""

# = Contributors =
# https://github.com/mmachicao: Port impapbackup core use case to python3.8.
# Mailbox does not support compression.
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

from dataclasses import dataclass


class SkipFolderException(Exception):
    """Custom exception. Aborting processing of current folder, continue with next folder."""


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
            self.pos = (self.pos + 1) % len(self.glyphs)

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
    if num < 1024:
        return f"{num} bytes"
    if num < 1048576:
        return f"{num / 1024.0:.2f} KB"
    if num < 1073741824:
        return f"{num / 1048576.0:.3f} MB"
    if num < 1099511627776:
        return f"{num / 1073741824.0:.3f} GB"

    return f"{num / 1099511627776.0:.3f} TB"


# Regular expressions for parsing
MSGID_RE = re.compile("^Message\-Id\: (.+)", re.IGNORECASE + re.MULTILINE)
BLANKS_RE = re.compile(r"\s+", re.MULTILINE)

# Constants
UUID = "19AF1258-1AAF-44EF-9D9A-731079D6FAD7"  # Used to generate Message-Ids


def string_from_file(value):
    """
    Read a string from a file or return the string unchanged.

    If the string begins with '@', the remainder of the string
    will be treated as a path to the file to be read.  Precede
    the '@' with a '\' to treat it as a literal.
    """
    assert isinstance(value, str)

    if not value or value[0] not in ["\\", "@"]:
        return value

    if value[0] == "\\":
        return value[1:]

    with open(os.path.expanduser(value[1:]), mode="r", encoding="utf-8") as content:
        return content.read().strip()


@dataclass
class DownloadOptions:
    """Options provided from the command line"""

    overwrite: bool
    nospinner: bool
    thunderbird: bool


def download_messages(server, filename, messages, opts, basedir):
    """Download messages from folder and append to mailbox"""

    fullname = os.path.join(basedir, filename)

    if opts.overwrite and os.path.exists(fullname):
        print(f"Deleting mbox: {filename} at: {fullname}")
        os.remove(fullname)

    # Open disk file for append in binary mode
    mbox = open(fullname, "ab")

    # the folder has already been selected by scanFolder()

    # nothing to do
    if len(messages) == 0:
        print("New messages: 0")
        mbox.close()
        return

    spinner = Spinner(
        f"Downloading {len(messages)} new messages to {filename}", opts.nospinner
    )
    total = biggest = 0
    from_re = re.compile(b"\n(>*)From ")

    # each new message
    for msg_id in messages.keys():
        # This "From" and the terminating newline below delimit messages
        # in mbox files.  Note that RFC 4155 specifies that the date be
        # in the same format as the output of ctime(3), which is required
        # by ISO C to use English day and month abbreviations.
        buf = f"From nobody {time.ctime()}\n"
        # If this is one of our synthesised Message-IDs, insert it before
        # the other headers
        if UUID in msg_id:
            buf = buf + f"Message-Id: {msg_id}\n"

        # convert to bytes before writing to file of type binary
        buf_bytes = bytes(buf, "utf-8")
        mbox.write(buf_bytes)

        # fetch message
        msg_id_str = str(messages[msg_id])
        typ, data = server.fetch(msg_id_str, "(RFC822)")
        assert "OK" == typ
        data_bytes = data[0][1]
        text_bytes = data_bytes.strip().replace(b"\r", b"")
        if opts.thunderbird:
            # This avoids Thunderbird mistaking a line starting "From  " as the start
            # of a new message. _Might_ also apply to other mail lients - unknown
            text_bytes = text_bytes.replace(b"\nFrom ", b"\n From ")
        else:
            # Perform >From quoting as described by RFC 4155 and the qmail docs.
            # https://www.rfc-editor.org/rfc/rfc4155.txt
            # http://qmail.org/qmail-manual-html/man5/mbox.html
            text_bytes = from_re.sub(b"\n>\\1From ", text_bytes)
        mbox.write(text_bytes)
        mbox.write(b"\n\n")

        size = len(text_bytes)
        biggest = max(size, biggest)
        total += size

        del data
        gc.collect()
        spinner.spin()

    mbox.close()
    spinner.stop()
    print(
        f": {pretty_byte_count(total)} total, {pretty_byte_count(biggest)} for largest message"
    )


def scan_file(filename, overwrite, nospinner, basedir):
    """Gets IDs of messages in the specified mbox file"""
    # file will be overwritten
    if overwrite:
        return []

    fullname = os.path.join(basedir, filename)

    # file doesn't exist
    if not os.path.exists(fullname):
        print(f"File {filename}: not found")
        return []

    spinner = Spinner(f"File {filename}", nospinner)

    # open the mailbox file for read
    mbox = mailbox.mbox(fullname)

    messages = {}

    # each message
    i = 0
    HEADER_MESSAGE_ID = "Message-Id"
    for message in mbox:
        header = ""
        # We assume all messages on disk have message-ids
        try:
            header = f"{HEADER_MESSAGE_ID}: {message.get(HEADER_MESSAGE_ID)}"

        except KeyError:
            # No message ID was found. Warn the user and move on
            print("")
            print(f"WARNING: Message #{i} in {filename}")
            print(f"has no {HEADER_MESSAGE_ID} header.")

        header = BLANKS_RE.sub(" ", header.strip())
        try:
            msg_id = MSGID_RE.match(header).group(1)
            if msg_id not in messages.keys():
                # avoid adding dupes
                messages[msg_id] = msg_id
        except AttributeError:
            # Message-Id was found but could somehow not be parsed by regexp
            # (highly bloody unlikely)
            print(f"WARNING: Message #{i} in {filename}")
            print(f"has a malformed {HEADER_MESSAGE_ID} header.")
        spinner.spin()
        i = i + 1

    # done
    mbox.close()
    spinner.stop()
    print(f": {len(messages.keys())} messages")
    return messages


def scan_folder(server, foldername, nospinner):
    """Gets IDs of messages in the specified folder, returns id:num dict"""
    messages = {}
    foldername = f'"{foldername}"'
    spinner = Spinner(f"Folder {foldername}", nospinner)
    try:
        typ, data = server.select(foldername, readonly=True)
        if "OK" != typ:
            raise SkipFolderException(f"SELECT failed: {data}")
        num_msgs = int(data[0])

        # Retrieve all Message-Id headers, making sure we don't mark all messages as read.
        #
        # The result is an array of result tuples with a terminating closing parenthesis
        # after each tuple. That means that the first result is at index 0, the second at
        # 2, third at 4, and so on.
        #
        # e.g.
        # [
        #   (b'1 (BODY[...', b'Message-Id: ...'), b')', # indices 0 and 1
        #   (b'2 (BODY[...', b'Message-Id: ...'), b')', # indices 2 and 3
        #   ...
        #  ]
        if num_msgs > 0:
            typ, data = server.fetch(
                f"1:{num_msgs}", "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])"
            )
            if "OK" != typ:
                raise SkipFolderException(f"FETCH failed: {data}")

        # each message
        for i in range(0, num_msgs):
            num = 1 + i

            # Double the index because of the terminating parenthesis after each tuple.
            data_str = str(data[2 * i][1], "utf-8", "replace")
            header = data_str.strip()

            # remove newlines inside Message-Id (a dumb Exchange trait)
            header = BLANKS_RE.sub(" ", header)
            try:
                msg_id = MSGID_RE.match(header).group(1)
                if msg_id not in messages.keys():
                    # avoid adding dupes
                    messages[msg_id] = num
            except (IndexError, AttributeError):
                # Some messages may have no Message-Id, so we'll synthesise one
                # (this usually happens with Sent, Drafts and .Mac news)
                msg_typ, msg_data = server.fetch(
                    str(num), "(BODY[HEADER.FIELDS (FROM TO CC DATE SUBJECT)])"
                )
                if "OK" != msg_typ:
                    raise SkipFolderException(f"FETCH {num} failed: {msg_data}")
                data_str = str(msg_data[0][1], "utf-8", "replace")
                header = data_str.strip()
                header = header.replace("\r\n", "\t").encode("utf-8")
                messages[
                    "<" + UUID + "." + hashlib.sha1(header).hexdigest() + ">"
                ] = num
            spinner.spin()
    finally:
        spinner.stop()
        print(
            ":",
        )

    # done
    print(f"{len(messages.keys())} messages")
    return messages


def parse_paren_list(row):
    """Parses the nested list of attributes at the start of a LIST response"""
    # eat starting paren
    assert row[0] == "("
    row = row[1:]

    result = []

    # NOTE: RFC3501 doesn't fully define the format of name attributes
    name_attrib_re = re.compile("^\s*(\\\\[a-zA-Z0-9_]+)\s*")

    # eat name attributes until ending paren
    while row[0] != ")":
        # recurse
        if row[0] == "(":
            paren_list, row = parse_paren_list(row)
            result.append(paren_list)
        # consume name attribute
        else:
            match = name_attrib_re.search(row)
            assert match is not None
            name_attrib = row[match.start() : match.end()]
            row = row[match.end() :]
            name_attrib = name_attrib.strip()
            result.append(name_attrib)

    # eat ending paren
    assert ")" == row[0]
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
    assert len(string_list) == 2
    return [paren_list] + string_list


def get_names(server, thunderbird, nospinner):
    """Get list of folders, returns [(FolderName,FileName)]"""
    spinner = Spinner("Finding Folders", nospinner)

    # Get LIST of all folders
    typ, data = server.list()
    assert typ == "OK"
    spinner.spin()

    names = []

    # parse each LIST entry for folder name hierarchy delimiter
    for row in data:
        row_str = str(row, "utf-8")
        lst = parse_list(row_str)  # [attribs, hierarchy delimiter, root name]
        delim = lst[1]
        foldername = lst[2]
        if thunderbird:
            filename = ".sbd/".join(foldername.split(delim))
            if filename.startswith("INBOX"):
                filename = filename.replace("INBOX", "Inbox")
        else:
            filename = ".".join(foldername.split(delim)) + ".mbox"
        # print "\n*** Folder:", foldername # *DEBUG
        # print "***   File:", filename # *DEBUG
        names.append((foldername, filename))

    # done
    spinner.stop()
    print(f": {len(names)} folders")
    return names


def print_usage():
    """Prints usage, exits"""
    #     "                                                                               "
    print("Usage: imapbackup [OPTIONS] -s HOST -u USERNAME [-p PASSWORD]")
    print(
        " -d DIR --mbox-dir=DIR         Write mbox files to directory. (defaults to cwd)"
    )
    print(" -a --append-to-mboxes         Append new messages to mbox files. (default)")
    print(
        " -y --yes-overwrite-mboxes     Overwite existing mbox files instead of appending."
    )
    print(
        " -f FOLDERS --folders=FOLDERS  Specify which folders to include. Comma separated list."
    )
    print(
        " --exclude-folders=FOLDERS     Specify which folders to exclude. Comma separated list."
    )
    print(
        "                               You cannot use both --folders and --exclude-folders."
    )
    print(" -e --ssl                      Use SSL.  Port defaults to 993.")
    print(
        " -k KEY --key=KEY              PEM private key file for SSL.  Specify cert, too."
    )
    print(
        " -c CERT --cert=CERT           PEM certificate chain for SSL.  Specify key, too."
    )
    print(
        "                               Python's SSL module doesn't check the cert chain."
    )
    print(
        " -s HOST --server=HOST         Address of server, port optional, eg. mail.com:143"
    )
    print(" -u USER --user=USER           Username to log into server")
    print(
        " -p PASS --pass=PASS           Prompts for password if not specified.  If the first"
    )
    print(
        "                               character is '@', treat the rest as a path to a file"
    )
    print(
        "                               containing the password.  Leading '' makes it literal."
    )
    print(" -t SECS --timeout=SECS        Sets socket timeout to SECS seconds.")
    print(
        " --thunderbird                 Create Mozilla Thunderbird compatible mailbox"
    )
    print(" --nospinner                   Disable spinner (makes output log-friendly)")
    sys.exit(2)


def process_cline():
    """Uses getopt to process command line, returns (config, warnings, errors)"""
    # read command line
    try:
        short_args = "aynekt:c:s:u:p:f:d:"
        long_args = [
            "append-to-mboxes",
            "yes-overwrite-mboxes",
            "ssl",
            "timeout",
            "keyfile=",
            "certfile=",
            "server=",
            "user=",
            "pass=",
            "folders=",
            "exclude-folders=",
            "thunderbird",
            "nospinner",
            "mbox-dir=",
        ]
        opts, extraargs = getopt.getopt(sys.argv[1:], short_args, long_args)
    except getopt.GetoptError:
        print_usage()

    warnings = []
    config = {
        "overwrite": False,
        "usessl": False,
        "thunderbird": False,
        "nospinner": False,
        "basedir": ".",
    }
    errors = []

    # empty command line
    if (len(opts) == 0) and (len(extraargs) == 0):
        print_usage()

    # process command line options and save in config. log warnings and errors
    process_options(opts, config, warnings, errors)

    # don't ignore extra arguments
    for arg in extraargs:
        errors.append("Unknown argument: " + arg)

    # done processing command line
    return config, warnings, errors


def process_options(options, config, warnings, errors):
    """process each command line option, save in config

    log errors and warnings
    """
    for option, value in options:
        if option in ("-d", "--mbox-dir"):
            config["basedir"] = value
        elif option in ("-a", "--append-to-mboxes"):
            config["overwrite"] = False
        elif option in ("-y", "--yes-overwrite-mboxes"):
            warnings.append("Existing mbox files will be overwritten!")
            config["overwrite"] = True
        elif option in ("-e", "--ssl"):
            config["usessl"] = True
        elif option in ("-k", "--keyfile"):
            config["keyfilename"] = value
        elif option in ("-f", "--folders"):
            config["folders"] = value
        elif option in ("--exclude-folders"):
            config["exclude-folders"] = value
        elif option in ("-c", "--certfile"):
            config["certfilename"] = value
        elif option in ("-s", "--server"):
            config["server"] = value
        elif option in ("-u", "--user"):
            config["user"] = value
        elif option in ("-p", "--pass"):
            try:
                config["pass"] = string_from_file(value)
            except OSError as ex:
                errors.append(f"Can't read password: {str(ex)}")
        elif option in ("-t", "--timeout"):
            config["timeout"] = value
        elif option == "--thunderbird":
            config["thunderbird"] = True
        elif option == "--nospinner":
            config["nospinner"] = True
        else:
            errors.append("Unknown option: " + option)


def check_config(config, warnings, errors):
    """Checks the config for consistency, returns (config, warnings, errors)"""
    if "server" not in config:
        errors.append("No server specified.")
    if "user" not in config:
        errors.append("No username specified.")
    if ("keyfilename" in config) ^ ("certfilename" in config):
        errors.append("Please specify both key and cert or neither.")
    if "keyfilename" in config and not config["usessl"]:
        errors.append("Key specified without SSL.  Please use -e or --ssl.")
    if "certfilename" in config and not config["usessl"]:
        errors.append("Certificate specified without SSL.  Please use -e or --ssl.")
    if "server" in config and ":" in config["server"]:
        # get host and port strings
        bits = config["server"].split(":", 1)
        config["server"] = bits[0]
        # port specified, convert it to int
        if len(bits) > 1 and len(bits[1]) > 0:
            try:
                port = int(bits[1])
                if port > 65535 or port < 0:
                    raise ValueError
                config["port"] = port
            except ValueError:
                errors.append(
                    "Invalid port.  Port must be an integer between 0 and 65535."
                )
    if "timeout" in config:
        try:
            timeout = int(config["timeout"])
            if timeout <= 0:
                raise ValueError
            config["timeout"] = timeout
        except ValueError:
            errors.append("Invalid timeout value.  Must be an integer greater than 0.")
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
        print("WARNING:", warning)

    # show errors, exit
    for error in errors:
        print("ERROR", error)
    if len(errors):
        sys.exit(2)

    # prompt for password, if necessary
    if "pass" not in config:
        config["pass"] = getpass.getpass()

    # defaults
    if "port" not in config:
        if config["usessl"]:
            config["port"] = 993
        else:
            config["port"] = 143
    if "timeout" not in config:
        config["timeout"] = 60

    # done!
    return config


def connect_and_login(config):
    """Connects to the server and logs in.  Returns IMAP4 object."""
    try:
        # either both set or both unset
        assert not ("keyfilename" in config) ^ ("certfilename" in config)
        if config["timeout"]:
            socket.setdefaulttimeout(config["timeout"])

        if config["usessl"] and "keyfilename" in config:
            print(f"Connecting to {config['server']} TCP port {config['port']},")
            print(f"SSL, key from {config['keyfilename']},")
            print(f"cert from {config['certfilename']} ")
            server = imaplib.IMAP4_SSL(
                config["server"],
                config["port"],
                config["keyfilename"],
                config["certfilename"],
            )
        elif config["usessl"]:
            print(f'Connecting to {config["server"]} TCP port {config["port"]}, SSL')
            server = imaplib.IMAP4_SSL(config["server"], config["port"])
        else:
            print(f'Connecting to {config["server"]} TCP port {config["port"]}')
            server = imaplib.IMAP4(config["server"], config["port"])

        # speed up interactions on TCP connections using small packets
        server.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        print('Logging in as {config["user"]}')
        server.login(config["user"], config["pass"])
    except socket.gaierror as e:
        (err, desc) = e
        print(f"ERROR: problem looking up server '{config['server']}' ({err} {desc})")
        sys.exit(3)
    except socket.error as e:
        if str(e) == "SSL_CTX_use_PrivateKey_file error":
            print(f"ERROR: error reading private key file '{config['keyfilename']}'")
        elif str(e) == "SSL_CTX_use_certificate_chain_file error":
            print(
                f"ERROR: error reading certificate chain file '{config['keyfilename']}'"
            )
        else:
            print(f"ERROR: could not connect to '{config['server']}' ({e})")

        sys.exit(4)

    return server


def create_basedir(basedir):
    """Test and create the base directory on disk
    Return False on failure"""
    if os.path.isdir(basedir):
        return True

    try:
        os.makedirs(basedir)
    except OSError as ex:
        print("ERROR:", ex)
        return False


def create_folder_structure(names, basedir):
    """Create the folder structure on disk"""

    # pylint: disable=unused-variable
    for imap_foldername, filename in sorted(names):
        disk_foldername = os.path.split(filename)[0]
        if disk_foldername:
            try:
                # print "*** makedirs:", disk_foldername  # *DEBUG
                disk_path = os.path.join(basedir, disk_foldername)
                os.makedirs(disk_path)
            except OSError as e:
                if e.errno != 17:
                    raise


def main():
    """Main entry point"""
    try:
        config = get_config()
        if config.get("folders") and config.get("exclude-folders"):
            print(
                "ERROR: You cannot use both --folders and --exclude-folders at the same time"
            )
            sys.exit(2)
        server = connect_and_login(config)
        names = get_names(server, config["thunderbird"], config["nospinner"])
        exclude_folders = []
        if config.get("folders"):
            dirs = list(map(lambda x: x.strip(), config.get("folders").split(",")))
            if config["thunderbird"]:
                dirs = [
                    i.replace("Inbox", "INBOX", 1) if i.startswith("Inbox") else i
                    for i in dirs
                ]
            names = list(filter(lambda x: x[0] in dirs, names))
        elif config.get("exclude-folders"):
            exclude_folders = list(
                map(lambda x: x.strip(), config.get("exclude-folders").split(","))
            )

        basedir = config.get("basedir")
        if basedir.startswith("~"):
            basedir = os.path.expanduser(basedir)
        else:
            basedir = os.path.abspath(config.get("basedir"))

        if not create_basedir(basedir):
            print(f"ERROR: Failed to verify/create base directory: {basedir}")
            sys.exit(-1)

        # for n, name in enumerate(names): # *DEBUG
        #   print n, name # *DEBUG
        create_folder_structure(names, basedir)

        for name_pair in names:
            try:
                foldername, filename = name_pair
                # Skip excluded folders
                if foldername in exclude_folders:
                    print(f'Excluding folder "{foldername}"')
                    continue

                fol_messages = scan_folder(server, foldername, config["nospinner"])
                fil_messages = scan_file(
                    filename, config["overwrite"], config["nospinner"], basedir
                )
                new_messages = {}
                for msg_id in fol_messages.keys():
                    if msg_id not in fil_messages:
                        new_messages[msg_id] = fol_messages[msg_id]

                # for f in new_messages:
                #  print "%s : %s" % (f, new_messages[f])

                opts = DownloadOptions(
                    config["overwrite"], config["nospinner"], config["thunderbird"]
                )

                download_messages(
                    server,
                    filename,
                    new_messages,
                    opts,
                    basedir,
                )

            except SkipFolderException as e:
                print(e)

        print("Disconnecting")
        server.logout()
    except socket.error as e:
        print("ERROR:", e)
        sys.exit(4)
    except imaplib.IMAP4.error as e:
        print("ERROR:", e)
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


if __name__ == "__main__":
    gc.enable()
    main()
