# This script is used to parse the library .SO file to get some offsets and
# write back to the source file, I could've done it using just the shell, but
# parsing text in shell is just too annoying for me.

import subprocess

filename = 'src/main.c'
#filename = 'test.txt'


def run_cmd (cmd):
    lines = []
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        lines.append(line)
    retval = p.wait()
    return lines


lines = run_cmd ('readelf -S vmi.so | grep got')
long_lines = []
for line in lines:
    long_lines.append(line.split())

#print(long_lines)

got_off = int(long_lines[0][3], 16)
got_len = int(long_lines[0][5], 16) / int(long_lines[0][6], 16)
gotplt_off = int(long_lines[1][3], 16)
gotplt_len = int(long_lines[1][5], 16) / int(long_lines[1][6], 16)

run_cmd ('sed -i "s/define GOT_OFF.*/define GOT_OFF '           + hex(got_off) + '/g" ' + filename)
run_cmd ('sed -i "s/define GOT_SIZE.*/define GOT_SIZE '         + hex(got_len) + '/g" ' + filename)
run_cmd ('sed -i "s/define GOTPLT_OFF.*/define GOTPLT_OFF '     + hex(gotplt_off) + '/g" ' + filename)
run_cmd ('sed -i "s/define GOTPLT_SIZE.*/define GOTPLT_SIZE '   + hex(gotplt_len) + '/g" ' + filename)

#print(got_off)
#print(got_len)
#print(gotplt_off)
#print(gotplt_len)

lines = run_cmd ('objdump -d vmi.so | grep "i686.get_pc_thunk.bx>:"')

thunk_off = int(lines[0].split()[0], 16)

run_cmd ('sed -i "s/define THUNK_OFF.*/define THUNK_OFF '   + hex(thunk_off) + '/g" ' + filename)
