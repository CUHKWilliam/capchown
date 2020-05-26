
import subprocess


def getCalledFunc(funcName='do_sys_open'):
    """
    use cscope to get all function name called by give funcName
    """
    process = subprocess.Popen(['cscope', '-dL2', funcName], stdout=subprocess.PIPE)
    stdout = process.communicate()[0]
    s = stdout.decode('utf-8')
    t = s.strip().split('\n')
    ret = {}
    for i in t:
        temp = i.split()
        fileName = temp[0]
        calledFuncName = temp[1]
        lineNum = temp[2]
        parameters = ' '.join(temp[3:])
        ret[calledFuncName] = [fileName, lineNum, parameters]
        #print(ret[calledFuncName])

    #print(ret.keys())
    #print ('STDOUT:\n{}'.format(s.strip()))
    #[print ('{}'.format(i)) for i in t]
    #print (len(t))
    #print (t)
    return ret

def getSinkFunc(capName='CAP_CHOWN'):
    """
    use cscope to get all function names contains the given CAP
    """
    process = subprocess.Popen(['cscope', '-dL0', capName], stdout=subprocess.PIPE)
    stdout = process.communicate()[0]
    s = stdout.decode('utf-8')
    t = s.strip().split('\n')
    ret = {}
    for i in t:
        temp = i.split()
        fileName = temp[0]
        calledFuncName = temp[1]
        if calledFuncName=='<global>':
            continue
        elif '.h' in fileName:
            continue
        lineNum = temp[2]
        parameters = ' '.join(temp[3:])
        ret[calledFuncName] = [fileName, lineNum, parameters]
        print(ret[calledFuncName])

    print(ret.keys())
    #print ('STDOUT:\n{}'.format(s.strip()))
    #[print ('{}'.format(i)) for i in t]
    #print (len(t))
    #print (t)
    return ret

def print_call_path(fpLog, call_list, infix=" -> ", prefix="==="):
    """
    """
    #print(call_list)
    fpLog.write(prefix)
    fpLog.write(infix.join(call_list))
    fpLog.write('\n')
    return


def search_inverse(fpLog, visited, funcName='chown_ok', sinkFuncList=['do_sys_open'], acc=['chown_ok']):
    """
    this is a recursive function
    funcName is the current function where we want to start our search
    acc[] is the list of accumulated path, which will be printed once any sink func is met
    acc[] is used for tail recursive
    """
    if len(sinkFuncList) == 0:
        print("empty sink function list, just return")
        return
    if funcName in visited:
        fpLog.write(format("xxx %s already visited\n") %(funcName, ))
        return
    visited.add(funcName)
    # -dL3 is looking for function s calling given funcName
    process = subprocess.Popen(['cscope', '-dL3', funcName], stdout=subprocess.PIPE)
    stdout = process.communicate()[0]
    s = stdout.decode('utf-8')
    t = s.strip().split('\n')
    #print("----" + funcName)
    #print(len(t))
    #print(t)
    parent_func_set = set()
    for i in t:
        if i == '': # means nothing returned
            continue
        temp = i.split()
        fileName = temp[0]
        if '.h' in fileName: # means it is in .h include file, which we should ignore
            continue
        callingFuncName = temp[1]
        #print(callingFuncName)
        if callingFuncName in sinkFuncList: # got it, print what we find
            print_call_path(fpLog, acc+[callingFuncName], infix=" <- ", prefix="@@@")
            return
        elif "SYSCALL_DEFINE" in callingFuncName: # here also defines a system call
            print_call_path(fpLog, acc+[callingFuncName], infix=" <- ", prefix="@@@")
            return
        else:
            parent_func_set.add(callingFuncName)
        #lineNum = temp[2]
        #parameters = ' '.join(temp[3:])
        #ret[callingFuncName] = [fileName, lineNum, parameters]
    for parent_func in parent_func_set:
        #fpLog.write(format("IN %s: -> %s, with existing %s\n" %(funcName, parent_func, str(visited))))
        #print((parent_func, visited))
        ttt = acc + [parent_func]
        print_call_path(fpLog, ttt, infix=" <- ")
        search_inverse(fpLog, visited, parent_func, sinkFuncList, ttt)


def search_cap(fpLog, visited, target_cap="CAP_CHOWN", system_call_list=["do_sys_open"]):
    """
    """
    process = subprocess.Popen(['cscope', '-dL0', target_cap], stdout=subprocess.PIPE)
    stdout = process.communicate()[0]
    s = stdout.decode('utf-8')
    t = s.strip().split('\n')
    child_func_set = set()
    for i in t:
        if i == '': # means nothing returned
            continue
        temp = i.split()
        fileName = temp[0]
        if '.h' in fileName: # means it is in .h include file, which we should ignore
            continue
        calledFuncName = temp[1]
        search_inverse(fpLog, visited, calledFuncName, system_call_list, acc=[calledFuncName])



def search(fpLog, visited, funcName='do_sys_open', sinkFuncList=['getname_flags'], acc=['do_sys_open']):
    """
    this is a recursive function
    funcName is the current function where we want to start our search
    acc[] is the list of accumulated path, which will be printed once any sink func is met
    acc[] is used for tail recursive
    """
    if len(sinkFuncList) == 0:
        print("empty sink function list, just return")
        return
    if funcName in visited:
        return
    visited.add(funcName)
    process = subprocess.Popen(['cscope', '-dL2', funcName], stdout=subprocess.PIPE)
    stdout = process.communicate()[0]
    s = stdout.decode('utf-8')
    t = s.strip().split('\n')
    #print("----" + funcName)
    #print(len(t))
    #print(t)
    child_func_set = set()
    for i in t:
        if i == '': # means nothing returned
            continue
        temp = i.split()
        fileName = temp[0]
        if '.h' in fileName: # means it is in .h include file, which we should ignore
            continue
        calledFuncName = temp[1]
        #print(calledFuncName)
        if calledFuncName in sinkFuncList: # got it, print what we find
            print_call_path(fpLog, acc+[calledFuncName], "@@@")
            return
        else:
            child_func_set.add(calledFuncName)
        #lineNum = temp[2]
        #parameters = ' '.join(temp[3:])
        #ret[calledFuncName] = [fileName, lineNum, parameters]
    for child_func in child_func_set:
        #fpLog.write(format("IN %s: -> %s, with existing %s\n" %(funcName, child_func, str(visited))))
        #print((child_func, visited))
        ttt = acc + [child_func]
        print_call_path(fpLog, ttt)
        search(fpLog, visited, child_func, sinkFuncList, ttt)


def buildPath(system_call='sys_do_open', cap='CAP_CHOWN'):
    """
    search all possible execution paths from src system-call to sink capabilities
    """
    sink_dict = getSinkFunc(cap)
    sink_set = list(sink_dict.keys())

    search(system_call, sink_set, [system_call])



if __name__ == '__main__':
    #getCalledFunc()
    #getSinkFunc()
    fpLog = open('/dev/shm/b.log', 'w')
    visited = set()
    #search(fpLog, visited)
    #search_inverse(fpLog, visited)
    #search_cap(fpLog, visited)
    #search_cap(fpLog, visited, "CAP_NET_RAW")
    search_cap(fpLog, visited)
    fpLog.close()
