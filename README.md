imapbackup
==========

A Python script for creating full backups of IMAP mailboxes

## Background

This was first published around 2007 (probably earlier) [on my personal site][tao], and it was originally developed to work around the then rather limited (ok, inconsistent) Mac OS X Mail.app functionality and allow me to back up my old mailboxes in a fully standard `mbox` format (well, at least as much as `mbox` can be considered a standard...).

Somewhat to my surprise it was considered useful by quite a few people throughout the years, and contributions started coming in. Given that there seems to be renewed interest in this as a systems administration tool, I'm posting the source code here and re-licensing it under the MIT license.

## Features

* ZERO dependencies.
* Copies every single message from every single folder (or a subset of folders) in your IMAP server to your disk.
* Does _incremental_ copying (i.e., tries very hard to not copy messages twice).
* Tries to do everything as safely as possible (only performs read operations on IMAP).
* Generates `mbox` formatted files that can be imported into Mail.app (just choose "Other" on the import dialog).
* Optionally compresses the result files on the fly (and can append to them).
* Is completely and utterly free (distributed under the MIT license).

## Requirements

This script should work on Python 2.5 or above without any extra dependencies whatsoever.

A word of caution, though: make sure to check the date format on the resulting `mbox` files, since it is dependent on your locale. For best results, it might be best to set `LOCALE` to `en-us` on your shell before running the script.

## Contributing

I am accepting pull requests, but bear in mind that one of the goals of this script is to run on _older_ Python versions, so as to save sysadmins stuck in the Dark Ages the trouble of installing a newer Python (much to my own amazement, this was originally written in Python 2.3).

I would be delighted to make it PEP8 compliant, bring it fully up to date with Python 2.7/3.4, etc., and have considered adding multi-threading/multiprocessing to speed it up, but time is short enough as it is. If you feel up to the task just send me a pull request with a "new" main script with the target Python version as part of its name - something like `imapbackup27.py`, etc.

# Disclaimer

For tradition's sake, here goes:

IN NO EVENT WILL I BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, THOSE RESULTING FROM LOST PROFITS, LOST DATA, LOST REVENUE OR BUSINESS INTERRUPTION) ARISING OUT OF THE USE, INABILITY TO USE, OR THE RESULTS OF USE OF, THIS PROGRAM. WITHOUT LIMITING THE FOREGOING, I SHALL NOT BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES THAT MAY RESULT FROM THE USE OF THIS SCRIPT OR ANY PORTION THEREOF WHETHER ARISING UNDER CONTRACT, NEGLIGENCE, TORT OR ANY OTHER LAW OR CAUSE OF ACTION. I WILL ALSO PROVIDE NO SUPPORT WHATSOEVER, OTHER THAN ACCEPTING FIXES AND UPDATING THE SCRIPT AS IS DEEMED NECESSARY.

[tao]: http://taoofmac.com/space/projects/imapbackup
