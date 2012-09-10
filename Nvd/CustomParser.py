#!/usr/bin/python
"""
This is a custom parser that returns data in dict{} form
It uses the standard sections and tag: data format
"""
import os
import sys
import re
import string

class CustomParser():
    def __init__(self):
        self.noise=0
        self.debug=0
        self.trace=0

    def __prime(self):
        """ Find each section [] and create a dict based on it
            and its tag: data components
        """
        if self.debug:
            print"_ParseDataFileByType(%s, %s, %s)" % (file, type, filter)

        options = {}

        section_begin = 0
        exclude_ws=re.compile('\s')
        exclude_comment=re.compile('^#')
        section_filter=re.compile('^\\[+[a-z_.0-9]+\\]',re.IGNORECASE)

        for line in self.lines:
            line = line.strip('\n')
            if exclude_ws.match(line):
                continue
            if exclude_comment.match(line):
                continue
            if section_filter.match(line):
                section = line.strip('[]\n')
                options[section] =  []
                continue

            if options.has_key(section):
                if len(line) == 0:
                    continue

                options[section].append(line)

        if len(options) == 0:
            self.options = {}
        else:
            self.options = options


    def sections(self):
        return self.options.keys()

    def get(self, section):
        return self.options[section]

    def read(self, file):
        try:
            c = open(file, 'r')
        except:
            raise
        else:
            try:
                self.lines = c.readlines()
                c.close()
            except:
                raise
            else:
                self.__prime()


if __name__ == "__main__":
    import os
    home_dir = os.environ['HOME']
    config_dir=("%s/.nvdcve" % home_dir)
    config_file=("%s/nvdcve.conf" % config_dir)

    cfg = CustomParser()

    print "Test 1"
    cfg.read(config_file)
    sections = cfg.sections()
    for section in sections:
        print section
    data = cfg.get(section)
    print section ,
    for d in data:
        print d

    print "Test 2"
    sections = cfg.sections()
    for section in sections:
        print section
        data = cfg.get(section)
        for d in data:
            print d
