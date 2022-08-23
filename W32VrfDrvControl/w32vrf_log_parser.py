import pykd
import os

from ctypes import *

'''
//Часть, расположенная в user mode памяти
typedef struct
{
	//Tag по котором можно найти лог в user mode памяти
	DWORD		dwTag;
	//Kernel Mode указатель на лог 
	//PPROCESS_MEMORY_LOG
	PVOID		pMemoryLog;
}USER_MODE_LOG_BUFFER, *PUSER_MODE_LOG_BUFFER;
'''
class USER_MODE_LOG_BUFFER(Structure):
    _fields_ = [("dwTag",c_ulonglong),
                ("pMemoryLog",c_void_p)]

'''
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
'''
class LIST_ENTRY(Structure):
    _fields_ = [("Flink",c_void_p),
                ("Blink",c_void_p)]

'''
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
'''
class UNICODE_STRING(Structure):
    _fields_ = [("Length",c_ushort),
                ("MaximumLength",c_ushort),
                ("Buffer",c_wchar_p)]

'''
//Структура логера
typedef struct _PROCESS_MEMORY_LOG
{
	//Список
	LIST_ENTRY	ListEntry;
	//Процесс, в контексте которого пишеться лог
	PEPROCESS	pEprocess;
	//Имя процесса
	UNICODE_STRING pProcessName;
	//Указатель на User Mode память
	PUSER_MODE_LOG_BUFFER	pUserModeLogBuffer;
	//Количество записей в логе
	DWORD		dwRecordsAmount;
	//Общий размер занятого пространства
	SIZE_T		UsedSize;
	//Список записей в логе
	LIST_ENTRY	LogRecordsList;
	//Блокировка
	FAST_MUTEX	kMutex;

}PROCESS_MEMORY_LOG, *PPROCESS_MEMORY_LOG;
'''
class PROCESS_MEMORY_LOG(Structure):
    _fields_ = [("ListEntry", LIST_ENTRY),
                ("pEprocess", c_void_p),
                ("pProcessName", UNICODE_STRING),
                ("pUserModeLogBuffer", POINTER(USER_MODE_LOG_BUFFER)),
                ("dwRecordsAmount", c_ulong),
                ("UsedSize", c_size_t),
                ("LogRecordsList", LIST_ENTRY),
                ("kMutex", c_byte * 0x34)]

'''
//Записи в логе
typedef struct
{
	//Список
	LIST_ENTRY	ListEntry;
	//Размер данной записи
	SIZE_T		cbSize;
	//Собственно туловище записи
	BYTE		pRecord[ANYSIZE_ARRAY];
}MEMORY_LOG_RECORD,*PMEMORY_LOG_RECORD;
'''
class MEMORY_LOG_RECORD(Structure):
    _fields_ = [("ListEntry", LIST_ENTRY),
                ("cbSize", c_size_t)]

class HEAP_RECORD_HEADER(Structure):
    _fields_ = [("FType", c_longlong),
                ("cbSize", c_size_t)]

'''
typedef	struct _RTL_ALLOCATE_HEAP_LOG_RECORD
{
	FUNCTION_TYPE	FType;
	SIZE_T	cbSize;
	PVOID	HeapHandle;
	ULONG	Flags;
	SIZE_T	Size;
	PVOID	pAddr;
	BYTE	pStack[MAXIMUM_STACK_SIZE];
}RTL_ALLOCATE_HEAP_LOG_RECORD, *PRTL_ALLOCATE_HEAP_LOG_RECORD;
'''
class RTL_ALLOCATE_HEAP_LOG_RECORD(Structure):
     _fields_ = [("FType", c_longlong),
                 ("cbSize", c_size_t),
                 ("HeapHandle", c_void_p),
                 ("Flags", c_longlong),
                 ("Size", c_size_t),
                 ("pAddr", c_void_p)]

'''
typedef struct _RTL_FREE_HEAP_LOG_RECORD
{
	FUNCTION_TYPE	FType;
	SIZE_T	cbSize;
	PVOID	HeapHandle;
	ULONG	Flags;
	PVOID	pAddr;
	BYTE	pStack[MAXIMUM_STACK_SIZE];
}RTL_FREE_HEAP_LOG_RECORD, *PRTL_FREE_HEAP_LOG_RECORD;
'''
class RTL_FREE_HEAP_LOG_RECORD(Structure):
    _fields_ = [ ("FType", c_longlong),
                 ("cbSize", c_size_t),
                 ("HeapHandle", c_void_p),
                 ("Flags", c_longlong),
                 ("pAddr", c_void_p)]

class heap_free_log_record():
    def __init__(self, heap_handle, addr, flags, pStack):
        self.heap_handle = heap_handle
        self.addr = addr
        self.flags = flags
        self.stack = pStack
        
    def get_stack_str(self, Len):
        return pykd.dbgCommand("dps " + hex(self.stack) + " L?" + str(Len))

class heap_alloc_log_record():
    def __init__(self, heap_handle, addr, size, flags, pStack):
        self.heap_handle = heap_handle
        self.addr = addr
        self.size = size
        self.flags = flags
        self.stack = pStack

    def get_stack_str(self, Len):
        return pykd.dbgCommand("dps " + hex(self.stack) + " L?" + str(Len))
        
class w32vrf_log_parser:
    def __init__(self):
        pykd.initialize()
        self.dump_id = None

        self.records = list()

    def load_dump(self, symbol_path, path):
        if not os.path.exists(path):
            return None

        pykd.setSymbolPath(symbol_path)

        self.dump_id = pykd.loadDump(path)

    def _get_first_log_record(self):
        #Search for user mode tag KLOG
        user_ptr = pykd.searchMemory(0x0, 0x10000000, 'KLOG')

        #Getting kernel mode pointer to PROCESS_MEMORY_LOG
        p_user_mem_log = pykd.loadBytes(user_ptr, sizeof(USER_MODE_LOG_BUFFER), False)
        user_mem_log = USER_MODE_LOG_BUFFER.from_buffer(bytearray(p_user_mem_log), 0)

        #Getting Log record list pointer
        p_process_mem_log = pykd.loadBytes(user_mem_log.pMemoryLog, sizeof(PROCESS_MEMORY_LOG), False)
        process_mem_log = PROCESS_MEMORY_LOG.from_buffer(bytearray(p_process_mem_log), 0)

        return process_mem_log.LogRecordsList

    def _set_context_fot_process(self, PID):

        out = pykd.dbgCommand(".sympath srv*E:\\symbols*http://msdl.microsoft.com/download/symbols/")
        out = pykd.dbgCommand("!reload")
        out = pykd.dbgCommand("!process 0 0")

        process_list = pykd.getTargetProcesses()

        for process in process_list:
            pass

    def parse_log(self):
        pykd.dbgCommand(".context 11fa29000")

        log_record_list = self._get_first_log_record()

        p_next_log_record = log_record_list.Flink
        next_log_record_buffer = pykd.loadBytes(p_next_log_record, sizeof(MEMORY_LOG_RECORD), False)
        next_log_record = MEMORY_LOG_RECORD.from_buffer(bytearray(next_log_record_buffer), 0)

        while "next_log_record != log_record_list":
            p_record_header = pykd.loadBytes(p_next_log_record + sizeof(MEMORY_LOG_RECORD), next_log_record.cbSize - sizeof(MEMORY_LOG_RECORD), False)
            record_header = HEAP_RECORD_HEADER.from_buffer(bytearray(p_record_header), 0)

            p_heap_record = pykd.loadBytes(p_next_log_record + sizeof(MEMORY_LOG_RECORD), record_header.cbSize, False)

            if record_header.FType == 0x0:
                heap_alloc_record = RTL_ALLOCATE_HEAP_LOG_RECORD.from_buffer(bytearray(p_heap_record), 0)
                log_record = heap_alloc_log_record( heap_alloc_record.HeapHandle, 
                                                    heap_alloc_record.pAddr, 
                                                    heap_alloc_record.Size, 
                                                    heap_alloc_record.Flags, 
                                                    p_next_log_record + sizeof(MEMORY_LOG_RECORD) + sizeof(RTL_ALLOCATE_HEAP_LOG_RECORD))
            else:
                heap_free_record = RTL_FREE_HEAP_LOG_RECORD.from_buffer(bytearray(p_heap_record), 0)
                log_record = heap_free_log_record(  heap_free_record.HeapHandle, 
                                                    heap_free_record.pAddr, 
                                                    heap_free_record.Flags, 
                                                    p_next_log_record + sizeof(MEMORY_LOG_RECORD) + sizeof(RTL_FREE_HEAP_LOG_RECORD))

            self.records.append(log_record)

            p_next_log_record = next_log_record.ListEntry.Flink
            next_log_record_buffer = pykd.loadBytes(p_next_log_record, sizeof(MEMORY_LOG_RECORD), False)
            next_log_record = MEMORY_LOG_RECORD.from_buffer(bytearray(next_log_record_buffer), 0)

            if log_record_list.Flink == next_log_record.ListEntry.Flink:
               break

        return self.records

    def save_log_to_file(self, path):

        f = open(path, "w")

        for log_record in self.records:
            result_str = ""

            if type(log_record) == heap_alloc_log_record:
                result_str += "HeapAlloc\r\n"
                result_str += "\tHeap Handle: {0:x}\r\n".format(log_record.heap_handle)
                result_str += "\tSize: {0:x}\r\n".format(log_record.size)
                result_str += "\tAddr: {0:x}\r\n".format(log_record.addr)
                result_str += "\nStack:\n{0:s}\r\n".format(log_record.get_stack_str(10))
                #print("HeapAlloc\r\n")
                #print("\tHeap Handle: {0:x}".format(log_record.heap_handle))
                #print("\tSize: {0:x}".format(log_record.size))
                #print("\tAddr: {0:x}".format(log_record.addr))
                #print("\nStack:\n{0:s}".format(log_record.get_stack_str(10)))
            elif type(log_record) == heap_free_log_record:
                result_str += "HeapFree\r\n"
                result_str += "\tHeap Handle: {0:x}\r\n".format(log_record.heap_handle)
                result_str += "\tAddr: {0:x}\r\n".format(log_record.addr)
                result_str += "\nStack:\n{0:s}\r\n".format(log_record.get_stack_str(10))
                #print("HeapFree")
                #print("\tHeap Handle: {0:x}".format(log_record.heap_handle))
                #print("\tAddr: {0:x}".format(log_record.addr))
                #print("\nStack:\n{0:s}".format(log_record.get_stack_str(10)))
            else:
                raise NotImplementedError("Not implemented save_log_to_file function")

            print(result_str)
            f.write(result_str)

        f.close()

    def close_dump(self):

        pykd.closeDump();