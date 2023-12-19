#!/usr/bin/env python3 -u

"""IMAP Incremental Backup Script"""
__version__ = "1.4h"
__author__ = "Rui Carmo (http://taoofmac.com)"
__copyright__ = "(C) 2006-2018 Rui Carmo. Code under MIT License.(C)"
__contributors__ = """jwagnerhki, Bob Ippolito, Michael Leonhard,
 Giuseppe Scrivano <gscrivano@gnu.org>, Ronan Sheth, Brandon Long,
 Christian Schanz, A. Bovett, Mark Feit, Marco Machicao"""

# = Contributors =
# https://github.com/mmachicao: Message ids are tracked in an sqlite3 database. Python3.8 and up only.
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
# - Add option to choose between file or db (default) scanning for downloaded message ids
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
import sqlite3
import logging

from dataclasses import dataclass

# constants used for sqlite3
SQLITE3_DATABASE_NAME = "message_ids.db"
SQL_CREATE_MESSAGE_TABLE_IF_MISSING = "CREATE TABLE IF NOT EXISTS messages (message_id TEXT, imapfolder TEXT, mailbox TEXT)"
SQL_CREATE_MESSAGE_INDEX_IF_MISSING = "CREATE INDEX IF NOT EXISTS idx_ids ON messages (imapfolder)"
SQL_SELECT_MESSAGE_IDS = "SELECT message_id FROM messages WHERE imapfolder = ?"
SQL_INSERT_MESSAGE_ID = "INSERT INTO messages (message_id, imapfolder, mailbox) VALUES (?, ?, ?)"
SQL_DELETE_MESSAGE_IDS = "DELETE FROM messages WHERE imapfolder = ?"


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
    """Some options provided from the command line"""
    basedir: str
    overwrite: bool
    nospinner: bool
    thunderbird: bool


def download_messages(server : imaplib.IMAP4, imapfolder : str, mailboxfile: str, message_ids : dict , opts : DownloadOptions):
    """
    Download messages from folder on server and append to mailbox file on disk.

    Reset mailbox and database, if overwrite mode is set.

    Throw SkipFolderException on errors

    in: imapfolder as known the IMAP server
    in: mailboxfile on disk
    in: message_ids : dict[message_id:fetch_id]
    Notes:

    - TODO:
    - Process in chunks of p messages or max q bytes
    - Close mailbox file and commit database after each chunk

    """

    fullname = os.path.join(opts.basedir, mailboxfile)

    dbfullname = os.path.join(opts.basedir, SQLITE3_DATABASE_NAME)

    # panic!
    if not os.path.exists(dbfullname):
        msg=f"{imapfolder}: version database does not exist"
        logging.error(msg)
        raise SkipFolderException(msg)

    # overwrite mode: reset database
    if opts.overwrite :
        msg=f"{imapfolder} : (download) : overwrite: resetting database"
        logging.info(msg)
        try:
            connection = None
            connection = sqlite3.connect(dbfullname)
            cursor = connection.cursor()
            cursor.execute(SQL_DELETE_MESSAGE_IDS,(imapfolder,))
            cursor.close()
        except Exception as ex:
            msg = f"{imapfolder} : (download) : overwrite: {ex}"
            logging.error(msg)
            raise SkipFolderException(ex.args)
        finally:
            if connection is not None:
                connection.close()


    # overwrite mode: delete mailbox and reset database
    if opts.overwrite and os.path.exists(fullname):
        msg=f"{imapfolder} : (download) : overwrite: resetting mailbox"
        logging.info(msg)
        try:
            os.remove(fullname)
        except OSError as ex:
            msg = f"{imapfolder} : (download) : overwrite: {ex}"
            logging.error(msg)
            raise SkipFolderException(ex.args)

    # TODO: Process all messages in chunks...

    msg=f"{imapfolder} : (download) : download messages: {len(message_ids)}"
    logging.info(msg)
    print(msg)

    connection = None
    try:
        connection = sqlite3.connect(dbfullname)
        cursor = connection.cursor()

        # Open disk file for append in binary mode
        with open(fullname, "ab") as mboxfile:

            # nothing to do. create mbox and leave
            if len(message_ids) == 0:
                return

            msg=f"{imapfolder} : (download) : downloading"
            spinner = Spinner(
                msg, opts.nospinner
            )
            total = biggest = 0
            from_re = re.compile(b"\n(>*)From ")

            # each new message
            for msg_id in message_ids.keys():
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
                mboxfile.write(buf_bytes)

                # fetch message
                # NOTE: Use the sequential fetch id provided by the server instead
                msg_fetch_id_str = str(message_ids[msg_id])
                typ, data = server.fetch(msg_fetch_id_str, "(RFC822)")
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
                mboxfile.write(text_bytes)
                mboxfile.write(b"\n\n")

                # register downloaded message_id in the database
                cursor.execute(SQL_INSERT_MESSAGE_ID, (msg_id, imapfolder, mailboxfile))

                size = len(text_bytes)
                biggest = max(size, biggest)
                total += size

                del data
                gc.collect()
                spinner.spin()
    except Exception as ex:
        msg=f"{imapfolder} : (download) : write messages: {ex}"
        logging.error(msg)
        print("")
        print(f"ERROR: {msg}")
    finally:
        if connection is not None:
            connection.commit()
            connection.close()


    spinner.stop()
    msg = f". total download: {pretty_byte_count(total)}, {pretty_byte_count(biggest)} for largest message"
    logging.info(f"{imapfolder} : (download): done{msg}")
    print(msg)


def scan_message_id_db(imapfolder: str, opts : DownloadOptions) -> dict:
    """ Read IDs of messages for the given imap folder from the local database on disk

    Return dict of msg_id:msg_id or throw SkipFolderException on error

    The dict will be empty when in owerwrite mode or the database does not exist
    """
    # no ids if overwrite mode has been requested
    if opts.overwrite:
        msg=f"{imapfolder} : (db) : message ids: 0 (overwrite mode)"
        logging.info(msg)
        return {}

    dbfullname = os.path.join(opts.basedir, SQLITE3_DATABASE_NAME)

    # no ids if database file hasn't been created yet...
    if not os.path.exists(dbfullname):
        msg=f"{imapfolder} : (db) : message ids: 0 (db not found. will be initialized)"
        logging.info(msg)
        return {}

    spinner = Spinner(f"{imapfolder} : (db) : reading message ids", opts.nospinner)

    # read message ids
    #
    # NOTE: Notice the comma at the end of filename.
    #       Otherwise, each character will be treated as an individual argument
    message_ids = {}

    try:
        connection = None
        connection = sqlite3.connect(dbfullname)
        cursor = connection.cursor()

        for ritem in cursor.execute(SQL_SELECT_MESSAGE_IDS,(imapfolder,)):
            message_ids[ritem[0]] = ritem[0]

        cursor.close()
    except Exception as ex:
        msg=f"{imapfolder} : (db) : {ex}"
        logging.error(msg)
        print(f"ERROR: {msg}")
        raise SkipFolderException(ex.args)
    finally:
        if connection is not None:
            connection.close()

    spinner.stop()

    # done
    logging.info(f"{imapfolder} : (db) : found message ids: {len(message_ids.keys())}")
    print(f": {len(message_ids.keys())}")
    return message_ids

def scan_mailbox_file(mailboxname : str, opts : DownloadOptions) -> dict:
    """Read IDs of messages in the local mailbox file on disk

    Return dict of msg_id:msg_id or None on errors
    """

    fullname = os.path.join(opts.basedir, mailboxname)

    # file hasn't been created yet...
    if not os.path.exists(fullname):
        msg=f"{mailboxname} : (file) : Mailbox file to be initialized"
        logging.info(msg)
        return {}

    spinner = Spinner(f"{mailboxname} : (file) : reading message ids", opts.nospinner)

    messages = {}

    # open the mailbox file for read
    mbox = mailbox.mbox(fullname)

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
            msg=f"{mailboxname} : (file) : WARNING : Message #{i} has no {HEADER_MESSAGE_ID} header."
            logging.warning(msg)
            print("")
            print(msg)

        header = BLANKS_RE.sub(" ", header.strip())
        try:
            msg_id = MSGID_RE.match(header).group(1)
            if msg_id not in messages.keys():
                # avoid adding dupes
                messages[msg_id] = msg_id
        except AttributeError:
            # Message-Id was found but could somehow not be parsed by regexp
            # (highly bloody unlikely)
            msg=f"{mailboxname} : (file) : WARNING : Message #{i} has a malformed {HEADER_MESSAGE_ID} header."
            logging.warning(msg)
            print("")
            print(msg)
        spinner.spin()
        i = i + 1

    mbox.close()
    spinner.stop()

    # done
    logging.info(f"{mailboxname} : (file) : found message ids: {len(messages.keys())}")
    print(f": {len(messages.keys())} messages")
    return messages

def sanitize_imap_folder_name(imapfolder: str) -> str:
    """ Add double quotes to imap folder names with SPACEs

    in: imapfoldername
    out sanitized folder name

    Examples:
    Trash -> Trash
    Sent Items -> "Sent Items"
    """
    if imapfolder.find(" ") < 0:
        return imapfolder

    if imapfolder[0] != '"':
        imapfolder = '"' + imapfolder
    if imapfolder[-1] != '"':
        imapfolder = imapfolder + '"'
    return imapfolder


def scan_imap_folder(server : imaplib.IMAP4, imapfolder : str, nospinner : bool):
    """Gets IDs of messages in the specified imapfolder.
    Returns id:num dict or SkipFolderException on error"""
    messages = {}
    spinner = Spinner(f'{imapfolder} : (imap) : reading message ids', nospinner)
    try:
        # handle folders with SPACEs
        folder = sanitize_imap_folder_name(imapfolder)
        typ, data = server.select(folder, readonly=True)
        if "OK" != typ:
            msg=f"{imapfolder} : (imap) : SELECT failed: {data}"
            logging.error(msg)
            raise SkipFolderException(msg)
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
                msg=f"{imapfolder} : (imap) : FETCH failed: {data}"
                logging.error(msg)
                raise SkipFolderException(msg)

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
                    msg=f"{imapfolder} : (imap) : FETCH {num} failed: {msg_data}"
                    logging.error(msg)
                    raise SkipFolderException(msg)

                data_str = str(msg_data[0][1], "utf-8", "replace")
                header = data_str.strip()
                header = header.replace("\r\n", "\t").encode("utf-8")
                messages[
                    "<" + UUID + "." + hashlib.sha1(header).hexdigest() + ">"
                ] = num
            spinner.spin()
    finally:
        spinner.stop()

    # done
    msg=f"{imapfolder} : (imap) : found message ids: {len(messages.keys())}"
    logging.info(msg)
    print(f": {len(messages.keys())}")
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


def parse_list_entry(row):
    """Parses response of LIST command into a list"""
    row = row.strip()
    paren_list, row = parse_paren_list(row)
    string_list = parse_string_list(row)
    assert len(string_list) == 2
    return [paren_list] + string_list


def imap_list_folders(server, thunderbird, nospinner):
    """Get list of folders, returns [(FolderName,FileName)]"""
    spinner = Spinner("Folders : (list)", nospinner)

    # Get LIST of all folders
    typ, data = server.list()
    assert typ == "OK"
    spinner.spin()

    names = []

    # parse each LIST entry for folder name hierarchy delimiter
    for row in data:
        row_str = str(row, "utf-8")
        logging.debug(f"parse_list: {row_str}")

        lst = parse_list_entry(row_str)  # [attribs, hierarchy delimiter, root name]
        delim = lst[1]
        foldername = lst[2]
        if thunderbird:
            filename = ".sbd/".join(foldername.split(delim))
            if filename.startswith("INBOX"):
                filename = filename.replace("INBOX", "Inbox")
        else:
            filename = ".".join(foldername.split(delim)) + ".mbox"

        logging.debug(f"list folders: foldername={foldername}, filename={filename}")
        names.append((foldername, filename))

    # done
    spinner.stop()
    msg=f": {len(names)} folders"
    print(msg)
    logging.info(f"Folders {msg}")
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
    print(" --DEBUG                       Set loglevel to DEBUG (default is INFO)")
    sys.exit(2)


def process_cline() -> (dict, list, list):
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
            "DEBUG"
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
        "loglevel": logging.INFO
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
        elif option == "--DEBUG":
            config["loglevel"] = logging.DEBUG
        else:
            errors.append("Unknown option: " + option)


def check_config(config : dict, warnings : list, errors : list) -> (dict, list, list):
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


def get_config() -> dict:
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


def imap_connect_and_login(config) -> ( imaplib.IMAP4 | imaplib.IMAP4_SSL):
    """Connects to the server and logs in.  Returns IMAP4 object."""
    try:
        msg=f'Login : (imap) : {config["server"]} as {config["user"]}'
        logging.info(msg)
        print(msg)

        # either both set or both unset
        assert not ("keyfilename" in config) ^ ("certfilename" in config)
        if config["timeout"]:
            socket.setdefaulttimeout(config["timeout"])

        if config["usessl"] and "keyfilename" in config:
            msg=f"Login : (imap) : Connecting to {config['server']} TCP port {config['port']},"
            logging.info(msg)
            msg=f"Login : (imap) : SSL, key from {config['keyfilename']},"
            logging.info(msg)
            msg=f"Login : (imap) : cert from {config['certfilename']} "
            logging.info(msg)
            server = imaplib.IMAP4_SSL(
                config["server"],
                config["port"],
                config["keyfilename"],
                config["certfilename"],
            )
        elif config["usessl"]:
            msg=f'Login : (imap) : Connecting to {config["server"]} TCP port {config["port"]}, SSL'
            logging.info(msg)
            server = imaplib.IMAP4_SSL(config["server"], config["port"])
        else:
            msg=f'Login : (imap) : Connecting to {config["server"]} TCP port {config["port"]}'
            logging.info(msg)
            server = imaplib.IMAP4(config["server"], config["port"])

        # speed up interactions on TCP connections using small packets
        server.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        server.login(config["user"], config["pass"])

    except socket.gaierror as e:
        (err, desc) = e
        msg = f"Login : (imap) : problem looking up server '{config['server']}' ({err} {desc})"
        logging.error(msg)
        print(f"ERROR: {msg}")
        sys.exit(3)
    except socket.error as e:
        if str(e) == "SSL_CTX_use_PrivateKey_file error":
            msg = f"Login : (imap) : error reading private key file '{config['keyfilename']}'"
            logging.error(msg)
            print(f"ERROR: {msg}")
        elif str(e) == "SSL_CTX_use_certificate_chain_file error":
            msg = f"Login : (imap) : error reading certificate chain file '{config['keyfilename']}'"
            logging.error(msg) 
            print(f"ERROR: {msg}")
        else:
            msg=f"Login : (imap) : could not connect to '{config['server']}' ({e})"
            logging.error(msg) 
            print(f"ERROR: {msg}")

        sys.exit(4)

    return server


def create_basedir(basedir : str) -> bool:
    """Test and create the base directory on disk
    Return False on failure"""
    if os.path.isdir(basedir):
        return True

    try:
        os.makedirs(basedir)
    except OSError as ex:
        logging.error(ex)
        print("ERROR: ", ex)
        return False

    return True


def create_folder_structure(names: list, basedir: str) -> bool:
    """Create the folder structure on disk
    Return false on errors
    """
    # pylint: disable=unused-variable
    for imap_foldername, filename in sorted(names):
        disk_foldername = os.path.split(filename)[0]
        if disk_foldername:
            try:
                disk_path = os.path.join(basedir, disk_foldername)
                os.makedirs(disk_path, exist_ok=True)
            except OSError as ex:
                logging.error(ex)

    return True

def create_database(basedir : str) -> bool:
    """ Create and initialize the message database
    Return false on errors
    """
    dbfullname = os.path.join(basedir, SQLITE3_DATABASE_NAME)

    if os.path.exists(dbfullname):
        return True

    try:
        logging.debug("INIT: initializing database")
        connection = None
        connection = sqlite3.connect(dbfullname)
        cursor = connection.cursor()
        cursor.execute(SQL_CREATE_MESSAGE_TABLE_IF_MISSING)
        cursor.execute(SQL_CREATE_MESSAGE_INDEX_IF_MISSING)
        cursor.close()
        return True
    except Exception as ex:
        logging.error(ex)
        return False
    finally:
        if connection is not None:
            connection.close()


def main():
    """Main entry point"""
    try:
        # load configuration
        config = get_config()
        if config.get("folders") and config.get("exclude-folders"):
            print(
                "ERROR: You cannot use both --folders and --exclude-folders at the same time"
            )
            sys.exit(2)

        # create basedir and setup logging
        basedir = config.get("basedir")
        if basedir.startswith("~"):
            basedir = os.path.expanduser(basedir)
        else:
            basedir = os.path.abspath(basedir)

        if not create_basedir(basedir):
            print(f"ERROR: Failed to verify/create base directory: {basedir}")
            sys.exit(-1)

        logfile = f"{basedir}{os.sep}imapbackup38.log"
        logging.basicConfig(filename=logfile, filemode='w', encoding='utf-8',
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            datefmt='%Y-%m-%d %I-%M-%S %p',
                            level=config["loglevel"]
                            )

        print(f"Logfile: {logfile}")

        server = imap_connect_and_login(config)
        names = imap_list_folders(server, config["thunderbird"], config["nospinner"])
        exclude_folders = []
        if config.get("folders"):
            dirs = list(map(lambda x: x.strip(), config.get("folders").split(",")))
            if config["thunderbird"]:
                dirs = [
                    i.replace("Inbox", "INBOX", 1) if i.startswith("Inbox") else i
                    for i in dirs
                ]
            names = list(filter(lambda x: x[0] in dirs, names))
            msg = f"(--folders) : {dirs}"
            logging.info(msg)
            print(f"Folders : {msg}")
            
        elif config.get("exclude-folders"):
            exclude_folders = list(map(lambda x: x.strip(), config.get("exclude-folders").split(",")))
            if config["thunderbird"]:
                exclude_folders = [
                    i.replace("Inbox", "INBOX", 1) if i.startswith("Inbox") else i
                    for i in exclude_folders
                ]
            names = list(filter(lambda x: x[0] not in exclude_folders, names))
            msg = f"(--exclude-folders) : {exclude_folders}"
            logging.info(msg)
            print(f"Folders : {msg}")

        logging.debug(f"Folders : (download) : {names}")
        
        opts = DownloadOptions(
                basedir, config["overwrite"], config["nospinner"], config["thunderbird"]
            )

        msg=f"Folders : (--yes-overwrite-mboxes) : {opts.overwrite}"
        logging.info(msg)
        print(msg)
        
        if not create_folder_structure(names, opts.basedir):
            msg = f"Failed to verify/create folder strcucture in: {opts.basedir} for names: {names}"
            logging.error(msg)
            print(f"ERROR: {msg}")
            sys.exit(-1)
        # create and initialize
        if not create_database(basedir):
            msg = f"Failed to create/open message_ids database in: {opts.basedir}"
            logging.error(msg)
            print(f"ERROR: {msg}")
            sys.exit(-1)

        for name_pair in names:
            try:
                imapfolder, mailboxfile = name_pair
                
                # read remote message ids. throws SkipFolderException on error
                fol_messages = scan_imap_folder(server, imapfolder, opts.nospinner)

                # read local message ids. throws SkipFolderException on error
                fil_messages = scan_message_id_db(imapfolder, opts)


                new_messages = {}
                for msg_id in fol_messages.keys():
                    if msg_id not in fil_messages:
                        new_messages[msg_id] = fol_messages[msg_id]

                download_messages(
                    server,
                    imapfolder,
                    mailboxfile,
                    new_messages,
                    opts
                )

            except SkipFolderException as e:
                logging.error(e)
                print("ERROR:",e)

        msg = "(done) : disconnect"
        logging.info(msg)
        print(msg)
        server.logout()
    except socket.error as e:
        logging.error(e)
        print("ERROR:", e)
        sys.exit(4)
    except imaplib.IMAP4.error as e:
        logging.error(e)
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
