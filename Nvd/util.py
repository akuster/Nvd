import sys
import re

def __version_parse(version):
    a1 = []

    # remove bogus rc"
    if re.search("rc", version):
        version = version.split("rc")[0]
        version = version[:-1]
    
    delimeter = re.search(".", version)
    if delimeter:
        if re.search("_", version):
            version = re.sub(r'_.*$',"", version)

        l1 = len(version.split("."))
        for l in range(0,l1):
            a1.append(version.split(".")[l])

    if delimeter == None:
        delimeter  = re.search("-", version)
        if delimeter:
            l1 = len(version.split("-"))
            for l in range(0,l1):
                a1.append(version.split("-")[l])

    if delimeter == None:
        delimeter = re.search("_", version)
        if delimeter:
            l1 = len(version.split("_"))
            for l in range(0,l1):
                a1.append(version.split("_")[l])

    return a1


def vcmp(arg1=None, arg2=None):
    ret = 0
    
    if not arg1 or not arg2:
        return None

    if re.search(r'^[a-zA-Z]', arg1) or re.search(r'^[a-zA-Z]', arg2):
        return None

    a1 = __version_parse(arg1)
    a2 = __version_parse(arg2)

    a1_len = int(len(a1))
    a2_len = int(len(a2))

    if a1_len > a2_len:
        max = a1_len
        for i in range(0, a1_len - a2_len):
            a2.append('0')

    elif a2_len > a1_len:
        max = a2_len
        for i in range(0, a2_len - a1_len):
            a1.append('0')
    else:
        max = a1_len

    for i in range(0, max):
        try:
            if int(a1[i]) == int(a2[i]):
                ret = 0
                continue
        except ValueError:
            pass
            ret = -3 
            break

        if int(a1[i]) > int(a2[i]):
            ret = 1
            break

        if int(a1[i]) < int(a2[i]):
            ret = -1
            break

    return ret

def inRange(target, lower, upper):
    ''' This will check if the target
        is between the lower and upper limits
        Return  True if within limits
                False if outside limits
    '''
    ret = False
    if upper == None:
        upper = lower

    # in this case we check if target is >= lower
    if lower == None:
        l = True
    else:
        ret = vcmp(target,lower)
        if ret == -3:
            return -3

        elif ret >= 0:
            l = True
        else:
            l = False

    # in this case we check if target is <= upper 
    ret = vcmp(target,upper)
    if ret == -3:
        return -3
    elif ret <= 0:
        u = True
    else:
        u = False

    if l and u:
        ret = True 

    if not l or not u:
        ret = False 

    return ret
        
def test(args):
    try:
        a1 = args[1]
    except IndexError:
        a1 = None
    try:
        a2 = args[2]
    except IndexError:
        a2 = None
    print a1
    print a2

    ret = inRange(a1, "2.6.10", "2.6.11")
    if ret:
        print "%s within limits" % a1
    else:
        print "Not in limits"

    
    ret = vcmp(a1,a2)
    if ret == 0:
        print "Equal"
    elif ret == 1:
        print "a1 is greater than a2"
    elif ret == -1:
        print "a1 is less than a2"
    else:
        print "Invalid return"


    return 0

if __name__ == "__main__":
    sys.exit(test(sys.argv))
