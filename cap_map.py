
import subprocess
import argparse
from graphviz import Digraph

MAX_DEPTH = 10

syscall_cap_map = dict()
edge = []

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


def update_edge_list(edge_list, path):
	for i in range(len(path) - 1):
		if [path[i], path[i+1]] not in edge_list:
			edge_list.append([path[i], path[i+1]])

def search_inverse(fpLog, funcName='chown_ok', sinkFuncList=['do_sys_open'], acc=['chown_ok'], depth=MAX_DEPTH):
    """
    this is a recursive function
    funcName is the current function where we want to start our search
    acc[] is the list of accumulated path, which will be printed once any sink func is met
    acc[] is used for tail recursive
    """
    if len(sinkFuncList) == 0:
        print("empty sink function list, just return")
        return
    if depth > MAX_DEPTH:
    	return
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
            update_edge_list(edge, acc + [callingFuncName])
        #elif "SYSCALL_DEFINE" in callingFuncName: # here also defines a system call
        #    print_call_path(fpLog, acc+[callingFuncName], infix=" <- ", prefix="@@@")
        #    update_edge_list(edge, acc + [callingFuncName])

        flag_update = add_val_list2dic(syscall_cap_map, callingFuncName, syscall_cap_map[funcName])
        # if no capacities add to calling function, stop recursing for the calling function
        if flag_update:
        	parent_func_set.add(callingFuncName)
        else:
        	fpLog.write("stop propagate from {} to {}\n".format(funcName, callingFuncName))

        #lineNum = temp[2]
        #parameters = ' '.join(temp[3:])
        #ret[callingFuncName] = [fileName, lineNum, parameters]
    for parent_func in parent_func_set:
        #fpLog.write(format("IN %s: -> %s, with existing %s\n" %(funcName, parent_func, str(visited))))
        #print((parent_func, visited))
        ttt = acc + [parent_func]
        #print_call_path(fpLog, ttt, infix=" <- ")
        search_inverse(fpLog, parent_func, sinkFuncList, ttt, depth + 1)


def add_val_list2dic(dic, key, val_list):
	"""
	Convenient function for adding val to the list of corresponding function
	dic: a dictionary, key is the name of function, val is the list of capabilities
	key: the function name
	val_list: the list of capacities
	return: 0 if val_list \in dic[key]; 1 otherwise
	"""
	flag_update = 0
	if key not in dic.keys():
		dic[key] = val_list
		flag_update = 1
	else:
		for i in range(len(val_list)):
			if val_list[i] not in dic[key]:
				dic[key].append(val_list[i])
				flag_update = 1
	return flag_update 

def draw_graph(edge, target_cap_list, system_call_list):
	graph = Digraph("digraph")
	vertex = []
	for aedge in edge:
		for avertex in aedge:
			if avertex not in vertex:
				vertex.append(avertex)
	for avertex in vertex:
		if avertex in system_call_list:
			graph.node(name=avertex, color="red")
		elif avertex in target_cap_list:
			graph.node(name=avertex, color="green")
		else:
			graph.node(name=avertex, color="black")
	for aedge in edge:
		graph.edge(aedge[0], aedge[1])
	graph.view()


def search_cap(fpLog, target_cap_list=["CAP_CHOWN"], system_call_list=["do_sys_open"]):
	"""
	"""

	# search for every function using capability, add to syscall_cap_map
	calledFuncNameList = []
	for j in range(len(target_cap_list)):
		process = subprocess.Popen(['cscope', '-dL0', target_cap_list[j]], stdout=subprocess.PIPE)
		stdout = process.communicate()[0]
		s = stdout.decode('utf-8')
		t = s.strip().split('\n')
		for i in t:
			if i == '': # means nothing returned
				continue
			temp = i.split()
			fileName = temp[0]
			if '.h' in fileName: # means it is in .h include file, which we should ignore
				continue
			calledFuncName = temp[1]
			# add capability to correspongding called function
			add_val_list2dic(syscall_cap_map, key=calledFuncName, val_list=[target_cap_list[j]])
			update_edge_list(edge, [target_cap_list[j], calledFuncName])
			if calledFuncName not in calledFuncNameList:
				calledFuncNameList.append(calledFuncName)
	print(calledFuncNameList)
	for i in range(len(calledFuncNameList)):
		search_inverse(fpLog, calledFuncNameList[i], system_call_list, acc=[calledFuncNameList[i]], depth=0)

	# print(syscall_cap_map)

	for i in range(len(system_call_list)):
		if system_call_list[i] in syscall_cap_map.keys():
			print("{}:{}".format(system_call_list[i], str(syscall_cap_map[system_call_list[i]])))
		else:
			print("no capabilities found for {}".format(system_call_list[i]))
	draw_graph(edge, target_cap_list, system_call_list)



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
    #fpLog = open('/dev/shm/b.log', 'w')
    parser = argparse.ArgumentParser()
    parser.add_argument("--syscall", nargs="+")
    parser.add_argument("--cap", nargs="+")
    parser.add_argument("--output_dir", default="./")
    parser.add_argument("--source_dir", default="./")
    args = parser.parse_args()
    output_dir = args.output_dir
    source_dir = args.source_dir
    fpLog = open(output_dir + "run.log", "w")
    cap_list = args.cap
    #search(fpLog, visited)
    #search_inverse(fpLog, visited)
    #search_cap(fpLog, visited)
    #search_cap(fpLog, visited, "CAP_NET_RAW")
    search_cap(fpLog, target_cap_list=args.cap, system_call_list=args.syscall)
    fpLog.close()
