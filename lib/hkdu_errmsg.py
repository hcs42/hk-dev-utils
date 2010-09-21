def msg(s):
  return s.replace('\n', ' ').replace('\r', ' ')

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
