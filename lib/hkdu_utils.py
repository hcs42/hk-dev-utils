#!/usr/bin/python

# This file is part of Heapkeeper Development Utilities (hkdu).
#
# hkdu is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# hkdu is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# hkdu.  If not, see <http://www.gnu.org/licenses/>.

# Copyright (C) 2010 Csaba Hoch

"""Utility module. Should be imported by all hkdu modules because it modifies
sys.path."""

from __future__ import with_statement

import logging
import optparse
import os
import re
import subprocess
import sys
import tempfile

import hkdu_errmsg

sys.path.append(os.path.join(os.getenv('HEAPKEEPER_DEV_DIR'), 'src'))

import hkutils
import hkshell


##### Global variables #####

logger = logging.getLogger('hkdu_utils')
SHA_LENGTH = 10
MAX_LINE_LENGTH = 79
TESTER_FUNS = []

def prints(s):
    print s

##### General utility functions #####

def iterate_on_file_lines(files):
    for file in files:
        with open(file) as f:
            for i, line in enumerate(f):
                line = re.sub(r'[\n\r]', '', line)
                yield file, i + 1, line

def get_lines(s):
    # FIXME: does not work in Mac/Windows
    lines = s.split('\n')
    if len(lines) > 0 and lines[-1] == '':
        lines = lines[:-1]
    return lines

def bash_escape(s):
    # We put `s` between quotes if contains any character like space that
    # is not mentioned here
    if re.match('^[-_a-zA-Z0-9./+=:]+$', s):
        return(s)
    else:
        return("'%s'" % s)

class CallResult(object):
    pass

def call(cmd, return_value='status', merge=True):
    logger.debug('Calling external command...')

    log = ['Command to be executed:']

    for arg in cmd:
        log.append(' ' + bash_escape(arg))

    logger.debug(''.join(log))

    sp_call = subprocess.call
    Popen = subprocess.Popen
    PIPE = subprocess.PIPE
    STDOUT = subprocess.STDOUT

    if return_value == 'object':
        stderr = (STDOUT if merge else PIPE)
        popen = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        popen.wait()
        result = CallResult()
        result.returncode = popen.returncode
        (stdoutdata, stderrdata) = popen.communicate()
        result.stdoutdata = stdoutdata
        result.stderrdata = stderrdata
        return result
    elif return_value == 'status':
        return sp_call(cmd)
    elif return_value == 'status+infolog':
        popen = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        logger.info(popen.communicate()[0])
        return popen.returncode
    elif return_value == 'stdout':
        return Popen(cmd, stdout=PIPE).communicate()[0]
    elif return_value == '(stdout,stderr)':
        return Popen(cmd, stdout=PIPE, stderr=PIPE).communicate()
    elif return_value == 'stdout+stderr':
        return Popen(cmd, stdout=PIPE, stderr=STDOUT).communicate()[0]
    else:
        assert(False)

def get_heapkeeper_dir():
    return os.getenv('HEAPKEEPER_DEV_DIR')

def mkstemp(*args, **kw):
    fd, filename = tempfile.mkstemp(*args, **kw)
    os.close(fd)
    return filename

def import_module(modname):
    """Imports a given module.

    **Argument:**

    - `modname` (str)

    **Returns:** module | ``None`` --  returns ``None`` if the module was not
    found.
    """

    try:
        return __import__(modname)
    except ImportError, e:
        if str(e) == ('No module named ' + modname):
            return None
        else:
            exc_info = sys.exc_info()
            raise exc_info[0], exc_info[1], exc_info[2]

editor_to_editor_list_fun = None

def editor_to_editor_list(editor):
    global editor_to_editor_list_fun
    if editor_to_editor_list_fun is None:
        hkcustomlib = import_module('hkcustomlib')
        if hkcustomlib is not None:
            editor_to_editor_list_fun = hkcustomlib.editor_to_editor_list
        else:
            editor_to_editor_list_fun = hkshell.editor_to_editor_list
    return editor_to_editor_list_fun(editor)


##### git utility functions #####

def expand_commit_list(args):
    """Expand commit list.

    Commit specifications like HEAD^5..HEAD will be expanded (in forward
    chronological order).

    **Argument:**

    - `args` ([str])

    **Returns:** [(str, str)]
    """

    commits = []
    for arg in args:
        if re.search('\.\.', arg):
            cmd = ['git', 'rev-list', arg]
        else:
            cmd = ['git', 'rev-parse', arg]
        out, err = call(cmd, '(stdout,stderr)')
        if err.strip() != '':
            msg = 'expand_commit_list:\n' + err
            logger.error(msg)
            raise hkutils.HkException(msg)
        commits += [(arg, sha) for sha in reversed(get_lines(out))]
    return commits

def commit_repr(commit):
    commitname, sha = commit
    if commitname == sha:
        return sha[:SHA_LENGTH]
    else:
        return '%s (%s)' % (commitname, sha[:SHA_LENGTH])

def git_clone(source, target):
    return call(['git', 'clone', '--no-checkout', source, target],
                'status+infolog')

def git_clone_if_needed(source, target):
    logger.debug('Cloning git if necessary...')
    if not os.path.exists(os.path.join(target, '.git')):
        os.makedirs(target)
        return git_clone(source, target)
    return 0

def git_checkout(commit):
    logger.debug('Checking out the given Heapkeeper version...')
    return call(['git', 'checkout', '--force', '--quiet', commit])

def git_all_files():
    # Current directory should be: Heapkeeper
    res = call(['git', 'ls-files'], 'stdout')
    files = get_lines(res)
    return [file for file in files if file != '' and os.path.isfile(file)]

def git_python_files():
    # Current directory should be: Heapkeeper
    all_files = git_all_files()
    python_files = []
    for file in all_files:
        if re.search('\.py$', file):
            python_files.append(file)
    return python_files

def git_source_files():
    # Current directory should be: Heapkeeper
    all_files = git_all_files()
    source_files = []
    for file in all_files:
        if not re.search(r'\.(ico|svg|png|jpg)$', file):
            source_files.append(file)
    return source_files


##### Parsing command-line options #####

def add_logging_options(parser):
    group = optparse.OptionGroup(parser, 'Logging options')
    group.add_option('--loglevel', dest='log_level',
                     help='Log level (CRITICAL, ERROR, WARNING, INFO or '
                     'DEBUG)', action='store', default='WARNING')
    group.add_option('--logfile', dest='log_file',
                     help='Debug level',
                     action='store')
    group.add_option('-q', '--quiet', dest='log_level',
                     help='Suppress errors: equivalent to "--loglevel CRITICAL"',
                     action='store_const', const='CRITICAL')
    group.add_option('--no-warnings', dest='log_level',
                     help='Suppress warnings: equivalent to "--loglevel ERROR"',
                     action='store_const', const='ERROR')
    group.add_option('-v', '--verbose', dest='log_level',
                     help='Verbose output: equivalent to "--loglevel INFO"',
                     action='store_const', const='INFO')
    group.add_option('-V', '--very-verbose', dest='log_level',
                     help='Very verbose output: equivalent to "--loglevel DEBUG"',
                     action='store_const', const='DEBUG')
    parser.add_option_group(group)

def add_testing_options(parser):
    tests_help = \
        ('''Tests to perform or not to perform, separated with a colon.
         Available tests: ''' + ', '.join(get_tester_names()) +
         '''.  Examples: "unittest:pylint" (perform only these tests),
         "-unittest:pylint" (perform all tests except these), "all" (all
         available tests). The default value is "-javascript".''')
    tests_help = re.sub('\\s+', ' ', tests_help)

    group = optparse.OptionGroup(parser, 'Testing options')
    group.add_option('-t', '--tests', dest='tests',
                      help=tests_help,
                      action='store', default='-javascript')
    group.add_option('--tmpdir', dest='tmp_dir',
                      help='Temporary directory to use',
                      action='store')
    group.add_option('--shalength', dest='sha_length',
                      help='Length of SHA1 hashes when printed',
                      action='store', type='int')
    group.add_option('--only-refs', dest='inline',
                      help='Print only references to the problem reports',
                      action='store_false', default=True)
    parser.add_option_group(group)

##### Initialization #####

def check_heapkeeper_dir():
    heapkeeper_dev_dir = os.getenv('HEAPKEEPER_DEV_DIR')
    logger.debug('HEAPKEEPER_DEV_DIR=' + repr(heapkeeper_dev_dir))

    ok = False
    if heapkeeper_dev_dir is None:
        errmsg = hkdu_errmsg.HK_DEV_DIR_NOT_SET
    elif not os.path.exists(heapkeeper_dev_dir):
        errmsg = hkdu_errmsg.HK_DEV_DIR_DOES_NOT_EXIST % heapkeeper_dev_dir
    elif not os.path.isdir(heapkeeper_dev_dir):
        errmsg = hkdu_errmsg.HK_DEV_DIR_IS_A_FILE % heapkeeper_dev_dir
    else:
        ok = True

    if ok:
        return heapkeeper_dev_dir
    else:
        logger.error(errmsg)
        sys.exit(1)

def start_logging(options=None):
    level_str = getattr(options, 'log_level', 'ERROR').upper()
    level = getattr(logging, level_str)
    kw = {'level': level}
    if getattr(options, 'log_file', None) is not None:
        kw['filename'] = options.log_file
    logging.basicConfig(**kw)

def init_sha_length(options):
    global SHA_LENGTH
    if options.sha_length is not None:
        SHA_LENGTH = int(options.sha_length)

def set_tmp_dir(tmp_dir_arg):
    global tmp_dir
    tmp_dir = tmp_dir_arg

def set_up_tmp_dir(tmp_dir=None):
    logger.debug('Setting up the temporary directory...')
    if tmp_dir is None:
        tmp_dir = tempfile.mkdtemp(prefix='heapkeeper_tmpdir_')
    logger.info('Using the following temporary directory: %s' % tmp_dir)
    set_tmp_dir(tmp_dir)

def mkdir_p(dir):
    if not os.path.exists(dir):
        os.makedirs(dir)
    assert(os.path.isdir(dir))

def create_get_hkdu_dir():
    hkdu_dir = os.path.join(os.getenv('HOME'), '.hk-dev-utils')
    mkdir_p(hkdu_dir)
    mkdir_p(os.path.join(hkdu_dir, 'testresults'))
    return hkdu_dir

##### Testing functions (framework) #####

def tester_fun(testname):
    """This function is a decorator that adds a function to the dictionary of
    tester funcions."""
    def inner(f):
        global TESTER_FUNS
        TESTER_FUNS.append((testname, f))
        return f
    return inner

def run_test(testname, testfun, prefix='', inline=True):

    # Executing the test
    logger.info('Running the %s test...' % testname)
    passed, res = testfun()

    # Examining the results
    if passed:
        logger.info('...the %s test passed' % testname)
    else:
        logger.info('...the %s test reported problems' % testname)
        caption = ('%sproblems reported by the %s test' %
                   (prefix, testname))
        if inline:
            sep = '#' * 79
            prints('%s\n\n%s\n%s\n' % (caption, res.strip(), sep))
        else:
            tmpprefix = testname + '_test_'
            filename = mkstemp(dir=tmp_dir, prefix=tmpprefix)
            hkutils.string_to_file(res, filename)
            msg = 'The %s test reported problems: see the output in %s' % \
                  (testname, filename)
            prints('%s%s' % (prefix, msg))
    return passed, res

def check_testname(testname):
    if testname not in get_tester_names():
        logger.error('Unknown test name: ' + testname)
        return False
    else:
        return True

def expand_test_list(tests):

    logger.debug('Expanding test list...')

    specifying_skipped_tests = False
    if isinstance(tests, str) or isinstance(tests, unicode):
        if tests.startswith('-'):
            specifying_skipped_tests = True
            tests = tests[1:]
        tests = tests.split(':')

    if tests == ['all']:
        tests_expanded = get_tester_names()
    elif specifying_skipped_tests:
        tests_expanded = get_tester_names()
        for test in tests:
            if check_testname(test):
                tests_expanded.remove(test)
    else:
        tests_expanded = []
        for test in tests:
            if check_testname(test):
                tests_expanded.append(test)
    return tests_expanded

def run_tests(tests, prefix='', inline=True):

    tests_expanded = expand_test_list(tests)
    logger.debug('Executing tests: ' + repr(tests_expanded))
    for testname in tests_expanded:
        logger.debug('Trying to execute test %s...' % testname)
        matching_testers = \
            [testfun_it for testname_it, testfun_it in TESTER_FUNS
             if testname_it == testname]
        if len(matching_testers) != 0:
            testfun = matching_testers[-1]
            run_test(testname, testfun, prefix, inline)
        else:
            logger.error('Unknown test: ' + repr(test))

def test_commits(commits, tests, inline=True):
    logger.debug('Testing commits...')
    for commit in commits:
        commitname, sha = commit
        commit_str = commit_repr(commit)
        logger.info('Testing commit ' + commit_str)
        git_checkout(sha)
        run_tests(tests, commit_str + ': ', inline)

def get_tester_names():
    return [testname for testname, testfun in TESTER_FUNS]

##### Tester functions #####

@tester_fun(testname='unittest')
def unittest_tester():
    """Executes the unittests on Heapkeeper (src/test.py)."""

    res = call(['src/test.py'], return_value='stdout+stderr')
    passed = bool(re.match(r'^[-\s]+[\n\r]+Ran.*[\n\r]+OK[\n\r]*$', res))
    return (passed, res)

@tester_fun(testname='pylint')
def pylint_tester():
    """Runs pylint to check the Heapkeeper source code."""

    # Setting $PYTHONPATH
    python_files = git_python_files()
    python_dirs = set()
    for file in python_files:
        python_dirs.add(os.path.abspath(os.path.dirname(file)))
    python_path = ':'.join(sorted(python_dirs)) + ':' + os.getenv('PYTHONPATH')
    os.environ['PYTHONPATH'] = python_path

    # Calling pylint
    res = call(['pylint', '--reports=n', '--include-ids=y',
                '--rcfile=etc/pylintrc'] +
                python_files,
                return_value='stdout+stderr')

    # Examining the result
    if re.match(r'^\s*$', res):
        return (True, res)
    else:
        return (False, res)

@tester_fun(testname='linelength')
def linelength_tester():
    # Current directory should be: Heapkeeper

    # Finding bad lines
    bad_lines = []
    for file, i, line in iterate_on_file_lines(git_python_files()):
        if len(line.decode('utf8')) > MAX_LINE_LENGTH:
            if re.search('http://', line):
                # This is probably OK; if a link is more then 80 lines
                # long, the best is to keep it in one line
                pass
            else:
                bad_lines.append('%s:%s:%s\n' % (file, i, line))

    # Examining the results
    return (bad_lines == [], ''.join(bad_lines))

@tester_fun(testname='trailingwhitespace')
def trailingwhitespace_tester():
    # Current directory should be: Heapkeeper

    # Finding bad lines
    bad_lines = []
    for file, i, line in iterate_on_file_lines(git_source_files()):
        if len(line) > 0 and line[-1] in (' ', '\t'):
            bad_lines.append('%s:%s:%s\n' % (file, i, line))

    # Examining the results
    return (bad_lines == [], ''.join(bad_lines))

@tester_fun(testname='trailingline')
def trailingline_tester():
    # Current directory should be: Heapkeeper

    # Finding bad files
    bad_files = []
    for file in git_source_files():
        file_content = hkutils.file_to_string(file)
        if re.search(r'[\n\r][\n\r]$', file_content):
            bad_files.append(file)

    # Examining the results
    bad_files_2 = [file + '\n' for file in bad_files]
    return (bad_files == [], ''.join(bad_files_2))

@tester_fun(testname='javascript')
def javascript_tester():
    # Current directory should be: Heapkeeper

    # This test will have problems when more than one wants to run at the same
    # time, because the second one will not be able to reserve port 8081.

    cfg_file = mkstemp(dir=tmp_dir, prefix='javascript.cfg.')
    js_tmp_dir = tempfile.mkdtemp(dir=tmp_dir, prefix='javascript.heap')
    s = ('[heaps/myheap]\n'
         'path=%s\n' % js_tmp_dir)
    hkutils.string_to_file(s, cfg_file)

    # We use port 8081 so that we don't disturb the service running on 8080
    # (e.g a Heapkeeper web server). We sleep 5 seconds in the end to make sure
    # that the browser has the time to finish the request.
    call(['src/hk.py', '--configfile', cfg_file, '--hkrc', 'NONE',
        '-c', 'import hkweb',
        '-c', 'hkweb.start(8081)',
        '-c', 'import subprocess',
        '-c', ('subprocess.call(["google-chrome",'
               '"localhost:8081/static/html/test.html"])'),
        '-c', 'import time',
        '-c', 'time.sleep(5)',
        '--noshell'])

    # We can't decide whether the tests passed or failed; the user has to do
    # that by looking at the opened browser.
    return (True, '')

@tester_fun(testname='makedoc')
def unittest_tester():
    """Executes "make" in the documentation directory of Heapkeeper."""

    old_dir = os.getcwd()
    os.chdir('doc')
    res = call(['make', 'clean'], return_value='object')
    assert res.returncode == 0
    res = call(['make', 'strict'], return_value='object')
    passed = (res.returncode == 0)
    os.chdir(old_dir)
    return (passed, res.stdoutdata)

@tester_fun(testname='commitlog')
def unittest_tester():
    """Checks the log of the last commit.

    The following things are checked:

    - The first line of the commit log is not longer than 50 characters.
    - The second line of the commit log is empty.
    - The third line of the commit log is written between square brackets.
    - If there is a fourth line, it should be empty.
    """

    res = call(['git', 'log', '-n1'], return_value='object')
    assert res.returncode == 0
    lines = get_lines(res.stdoutdata)

    # Removing the header lines
    commit_log_lines = []
    in_commit_log = False  # we have reached the commit log
    for line in lines:
        if in_commit_log:
            commit_log_lines.append(line)
        elif line == '':
            in_commit_log = True
    lines = commit_log_lines

    # Removing indentation from each line
    lines = [line[4:] for line in lines]

    errors = []
    if len(lines) < 3:
        errors.append('Too few lines.')
    elif len(lines[0]) > 50:
        errors.append('First line too long.')
    elif len(lines[1]) > 0:
        errors.append('Second line should be empty.')
    elif not ((len(lines[2]) > 3) and
              (lines[2][0] == '[') and
              (lines[2][-1] == ']')):
        errors.append('The commit topic is not correct.')
    elif (len(lines) >= 4 and lines[3] != ''):
        errors.append('Line 4 should be empty.')

    if errors == []:
        passed = True
        result = res.stdoutdata
    else:
        passed = False
        errors = ''.join(errors) + '\n\n' + res.stdoutdata
    return (passed, errors)

