import re

def msg(s):
    """Converts the given string into a format that is best to print on the
    terminal.

    Single line endings will be removed.

    **Argument:**

    - `s` (str)

    **Returns:** str

    **Example:**

    >>> msg('''\\
    ... You should execute
    ... this command first:
    ...
    ...     $ cat
    ... ''')
    You should execute this command first:

        $ cat
    """

    # Line endings
    s = re.sub(r'\r\n', r'\n', s) # DOS: CR LF -> LF
    s = re.sub(r'\r', r'\n', s)   # Mac: CR -> LF

    # Removing single \n characters
    s = re.sub(r'\n(\n*)', r' \1', s)
    s = re.sub(r'(\n+)', r' \n\1', s)

    return s

HK_DEV_DIR_NOT_SET = msg('''\
The HEAPKEEPER_DEV_DIR environment variable is not set. It should point to the
directory that contains the master version of Heapkeeper and its git
repository.''')

HK_DEV_DIR_DOES_NOT_EXIST = msg('''\
The HEAPKEEPER_DEV_DIR environment variable points to a non-existent
file/directory: %s''')

HK_DEV_DIR_IS_A_FILE = msg('''\
The HEAPKEEPER_DEV_DIR environment variable points to a file rather then a
directory: %s''')

NO_COMMIT_SPECIFIED = msg('''\
Wrong usage: no commit specified.''')

JS_TEXT = ('''\
Follow these steps:

1. Make sure you have at least Java 1.6:

    $ java -version

2. Download JsTestDriver into the "external" directory:

    $ wget http://js-test-driver.googlecode.com/files/JsTestDriver-1.2.2.jar
-O external/JsTestDriver.jar

3. Start the jsTestDriver server:

    $ java -jar external/JsTestDriver.jar --port 9876
--config etc/jsTestDriver/jsTestDriver.conf

4. Create a tab in a browser and open this URL:

    http://localhost:9876/capture

5. You can execute the test again.
''')

JS_TEST_DRIVER_SERVER_NOT_RUNNING = msg('''\
It seems that the jsTestDriver server is not running.
''' +
JS_TEXT +
'''\
The original output of jsTestDriver was the following:

%s
''')

JS_TEST_DRIVER_NO_BROWSER = msg('''\
There is no browser to which jsTestDriver could connect. Create a tab in a
browser and open this URL:

    http://localhost:9876/capture

Afterwards execute the test again.

The original output of jsTestDriver was the following:

%s
''')

JS_TEST_DRIVER_UNRECOGNIZED_OUTPUT = msg('''\n
Unrecognized output from jsTestDriver.

Try to:
- reopen this tab in the browser: http://localhost:9876/capture
- restart the server

The original output of jsTestDriver was the following:
%s
''')

JS_TEST_DRIVER_NO_JAR = msg('''\n
JsTestDriver.jar not found at %s.
''' +
JS_TEXT)
