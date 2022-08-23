import os
import sys
import subprocess
import time
import random
import binascii
import win32con
import win32file
import winioctlcon
import pywintypes
import win32event

class w32vrf_device:
    def __init__(self):
        self.driver_dos_name = '\\\\.\\W32VrfDrv'
        self.driver_name = ""
        self.service_name = 'W32VrfDrv'
        self.w32vrf_device = None

        self.ENABLE_MEMORY_HOOK_IOCTL = winioctlcon.CTL_CODE(
                                                        winioctlcon.FILE_DEVICE_UNKNOWN,
                                                        0x0,
                                                        winioctlcon.METHOD_BUFFERED,
                                                        winioctlcon.FILE_ANY_ACCESS
                                                        )

        self.DISABLE_MEMORY_HOOK_IOCTL = winioctlcon.CTL_CODE(
                                                        winioctlcon.FILE_DEVICE_UNKNOWN,
                                                        0x1,
                                                        winioctlcon.METHOD_BUFFERED,
                                                        winioctlcon.FILE_ANY_ACCESS
                                                        )

        self.ADD_PROCESS_HOOK_IOCTL = winioctlcon.CTL_CODE(
                                                        winioctlcon.FILE_DEVICE_UNKNOWN,
                                                        0x2,
                                                        winioctlcon.METHOD_BUFFERED,
                                                        winioctlcon.FILE_ANY_ACCESS
                                                        )

        self.REMOVE_PROCESS_HOOK_IOCTL = winioctlcon.CTL_CODE(
                                                        winioctlcon.FILE_DEVICE_UNKNOWN,
                                                        0x3,
                                                        winioctlcon.METHOD_BUFFERED,
                                                        winioctlcon.FILE_ANY_ACCESS
                                                        )

    def start_w32vrf(self, driver_path):    
        self.driver_name = os.path.basename(driver_path)

        print("Install driver " + self.driver_name)

        self.stop_w32vrf()

        self.system_dbgprint("echo F | xcopy " + driver_path + " C:\\Windows\\system32\\drivers\\" + self.driver_name + " /Y")

        self.system_dbgprint('sc create ' + self.service_name + ' binPath= "C:\\Windows\\system32\\drivers\\' + self.driver_name + '" type= kernel start= demand error= normal')
        self.system_dbgprint('sc start ' + self.service_name)

        if self.w32vrf_device == None:
            self.w32vrf_device = win32file.CreateFile(
                                self.driver_dos_name,
                                win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                                None,
                                win32con.OPEN_EXISTING,
                                win32con.FILE_ATTRIBUTE_NORMAL | win32con.FILE_FLAG_OVERLAPPED,
                                None
                                )

    def w32vrf_enable_hook(self):
        if self.w32vrf_device != None:
            out = win32file.DeviceIoControl(
                                self.w32vrf_device,
                                self.ENABLE_MEMORY_HOOK_IOCTL,
                                None,
                                None,
                                None
                                )

    def w32vrf_disable_hook(self):
        if self.w32vrf_device != None:
            out = win32file.DeviceIoControl(
                                self.w32vrf_device,
                                self.DISABLE_MEMORY_HOOK_IOCTL,
                                None,
                                None,
                                None
                                )

    def w32vrf_close_device(self):
        if self.w32vrf_device != None:
            print("Close driver " + self.driver_dos_name)

            self.w32vrf_device.Close()

            self.w32vrf_device = None

    def stop_w32vrf(self):

        self.w32vrf_disable_hook()
        self.w32vrf_close_device()

        print('Stop ' + self.service_name)
        self.system_dbgprint('sc stop ' + self.service_name)
        self.system_dbgprint('sc delete ' + self.service_name)
        self.system_dbgprint('del C:\\Windows\\system32\\drivers\\' + self.driver_name)

    def w32vrf_add_process(self, process_binary_name):
        
        if self.w32vrf_device == None:
            return

        print("Add process " + process_binary_name)

        #u_proc_name = (u'' + process_binary_name).encode('utf-8')
        u_proc_name = process_binary_name.encode('utf-16le')

        buf_size = len(u_proc_name)
        out = win32file.DeviceIoControl(
                self.w32vrf_device,
                self.ADD_PROCESS_HOOK_IOCTL,
                u_proc_name,
                buf_size,
                None
        )

    def hv_remove_process(self, process_binary_name):
        if self.w32vrf_device == None:
            return

        print("Remove process " + process_binary_name)

        u_proc_name = process_binary_name.encode('utf-16le')

        buf_size = len(u_proc_name)
        out = win32file.DeviceIoControl(
                self.w32vrf_device,
                self.REMOVE_PROCESS_HOOK_IOCTL,
                u_proc_name,
                buf_size,
                None
        )

    def system_dbgprint(self, cmd):
        print(cmd)
        os.system(cmd)
