#!/usr/bin/env python

###
# dumpfilter
# advanced core dump filter
###

VERSION=(0,1,0)

import sys
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
import os, os.path
import functools
import gzip
import subprocess
import collections
import datetime
import shlex
import syslog

jpath = os.path.join

config = ConfigParser.SafeConfigParser()

syslog.openlog("dumpfilter")

class Process(collections.OrderedDict):
    def __init__(self, pid):
        super(Process, self).__init__()
        self.pid = pid
        self.proc = proc = functools.partial(os.path.join, "/proc", pid)
        self["cwd"] = os.readlink(proc("cwd"))
        self["exe"] = os.readlink(proc("exe"))
        self["cmdline"] = open(proc("cmdline")).read(-1).replace("\x00", " ")
        self["dump_status"] = "ok"
        self["crash_date"] = datetime.datetime.now()
        self.parse_status()
        self.dump_uid = int(self["Uid"].split("\t")[1])
        self.dump_gid = int(self["Gid"].split("\t")[3])
        # fixes
        self["pid"] = pid
        self["uid"] = self.dump_uid
        self.core = self.expand(config.get("general", "path"))
        if self.core.rfind(".") != -1:
            self.core_without_suffix = self.core[:self.core.rfind(".")]
        else:
            self.core_without_suffix = self.core
        self.core_info = self.expand(config.get("general", "path"))

    def parse_status(self):
        for line in open(self.proc('status')):
            chunks = line.split(":", 1)
            self[chunks[0]] = chunks[1].strip()

    def dump(self, fp):
        for k,v in self.iteritems():
            fp.write("%s:%s\n" %(k, v)) 

    def dump_file(self, template, rv_handle=False):
        fp = open(self.expand(template), "w+")
        self.dump(fp)
        if rv_handle:
            return fp
        fp.close()

    def expand(self, template):
        data = {}
        data.update(self)
        data.update(self.__dict__)
        return template.format(**data)


def parse_config(path=None, user=False):
    parser = ConfigParser.SafeConfigParser()
    # FIXME
    parser.read("/etc/dumpfilter/dumpfilter.ini")
    return parser

config = parse_config()

class Compressor(object):
    """
    GZip compressor.
    Tries to use pigz to do parallel compressions
    """
    def __init__(self, output, level=9):
        self.output = output
        self.output_real = os.path.realpath(output)
        self.check_free_blocks = None
        self.level = level
        self.out_fd = open(self.output, "w")
        try:
            self.pipe = subprocess.Popen(["pigz", "-%s" %level, ], shell=False, stdin=subprocess.PIPE, stdout=self.out_fd, bufsize=1024**2)
        except:
            self.pipe = None
            self.out_fd = gzip.GzipFile(filename=self.output, mode="w", compresslevel=self.level)

    def write(self, buffer):
        if self.pipe:
            self.pipe.stdin.write(buffer)
        else:
            self.out_fd.write(buffer)


    def close(self):
        if self.pipe:
            self.pipe.stdin.close()
            if self.pipe.wait() != 0:
                syslog.syslog(syslog.LOG_ERR, "There were errors in gzip pipe")
        else:
            self.out_fd.close()
        syslog.syslog(syslog.LOG_CRIT, "program crashed with coredump: %s" %self.output_real)

    def remove(self):
        self.out_fd.close()
        os.unlink(self.output_real)

    def check_free(self):
        if self.check_free_blocks == -1:
            return False

        fst = os.fstatvfs(self.out_fd.fileno())

        if not self.check_free_blocks and config.has_section("free"):
            best = None
            for ent in config.options("free"):
                if self.output_real[0:len(ent)] != ent:
                    continue
                if best and len(ent) > len(best):
                    best = ent
                else:
                    best = ent
            # no match at all ?
            if not best:
                return True
            # calculate the free block counter
            should = config.get("free", best)
            # percentage
            if should in ('off', 'disabled', 'disable', 'none'):
                self.check_free_blocks = -1
                return False

            elif should[-1] == "%":
                self.check_free_blocks = (fst.f_blocks/100)*int(should[:-1] or 10)
            else:
                factors = {
                        "k": 1000,
                        "m": 1000 ** 2,
                        "g": 1000 ** 3,
                        "t": 1000 ** 4,
                        "p": 1000 ** 5 }
                if factors.has_key(should[-1].lower()):
                    should = int(should[:-1]) * factors[should[-1].lower()]
                else:
                    # default to megabyte
                    should = int(should) * factors["m"]
                
                self.check_free_blocks = should / fst.f_frsize  # should be multiples of f_frsize, i guess
        # actual check
        if self.check_free_blocks is not None:
            if fst.f_bfree < self.check_free_blocks:
                return False

        return True

def dump_file(process):
    outpath = process.expand(config.get("general", "path"))
    out = Compressor(outpath)
    run = 0

    while True:
        chunk = sys.stdin.read()
        if not chunk:
            out.close()
            break
        out.write(chunk)

        # only check every 10 buffers, we can't estimate the real usage
        if run == 0:
            if not out.check_free():
                 # run out of space
                 process["dump_status"] = "error:not enough free space"
                 # remove dump file
                 out.remove()
                 break
            run = 10 
        run -= 1



if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("not enough arguments\n")
        sys.exit(1)
    
    process = Process(sys.argv[1])
    # change output working dir to process path and drop to user
    os.chdir(process["cwd"])
    os.setuid(process.dump_uid)

    # do the actual core dump
    dump_file(process)
    # dump info file
    handle = process.dump_file(config.get("general", "path_info"), True)
    # execute commands
    if config.has_section("commands"):
        for cn in config.options("commands"):
            handle.write("=" * 40 + "\n")
            cmd = process.expand(config.get("commands", cn))
            handle.write("RUN: " + cmd + "\n")
            try:
                sub = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
                x = sub.communicate()
                handle.write(x[0])
                # for some unknown reason, the pipe version with wait does not work... ?!?
                #if sub.wait() != 0:
                #    handle.write("exited with error code: " + sub.returncode)
            except (Exception, e):
                handle.write("\n" + str(e) + "\n")
            handle.write("=" * 40 + "\n")
    handle.close()
    sys.exit(0)



