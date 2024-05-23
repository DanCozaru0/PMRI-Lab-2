import ctypes
import json
import os
import psutil


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_char * 260)
    ]


def get_running_processes():
    try:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        TH32CS_SNAPPROCESS = 0x00000002
        hProcessSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if hProcessSnap == -1:
            raise ctypes.WinError(ctypes.get_last_error())

        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
        processes = []

        if not kernel32.Process32First(hProcessSnap, ctypes.byref(pe32)):
            kernel32.CloseHandle(hProcessSnap)
            raise ctypes.WinError(ctypes.get_last_error())

        while True:
            exe_file = pe32.szExeFile.decode('utf-8')
            processes.append({
                'ProcessID': pe32.th32ProcessID,
                'Executable': exe_file
            })

            if not kernel32.Process32Next(hProcessSnap, ctypes.byref(pe32)):
                break

        kernel32.CloseHandle(hProcessSnap)
        return processes

    except Exception as e:
        print(f"Error in get_running_processes: {e}")
        return []


def check_signature(file_path):
    try:
        wintrust = ctypes.WinDLL('wintrust', use_last_error=True)

        class WinTrustFileInfo(ctypes.Structure):
            _fields_ = [
                ("cbStruct", ctypes.c_ulong),
                ("pcwszFilePath", ctypes.c_wchar_p),
                ("hFile", ctypes.c_void_p),
                ("pgKnownSubject", ctypes.c_void_p)
            ]

        WTD_UI_NONE = 2
        WTD_REVOKE_NONE = 0
        WTD_CHOICE_FILE = 1
        WTD_STATEACTION_VERIFY = 1
        WINTRUST_ACTION_GENERIC_VERIFY_V2 = ctypes.create_string_buffer(
            b'\xa4\x68\x3a\x45\x2e\xf3\xd7\x5b\x68\xe9\x4b\xf8\x6e\xe0\x68\x13')

        class WinTrustData(ctypes.Structure):
            _fields_ = [
                ("cbStruct", ctypes.c_ulong),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", ctypes.c_ulong),
                ("fdwRevocationChecks", ctypes.c_ulong),
                ("dwUnionChoice", ctypes.c_ulong),
                ("pFile", ctypes.POINTER(WinTrustFileInfo)),
                ("dwStateAction", ctypes.c_ulong),
                ("hWVTStateData", ctypes.c_void_p),
                ("pwszURLReference", ctypes.c_wchar_p),
                ("dwProvFlags", ctypes.c_ulong),
                ("dwUIContext", ctypes.c_ulong)
            ]

        file_info = WinTrustFileInfo(
            cbStruct=ctypes.sizeof(WinTrustFileInfo),
            pcwszFilePath=file_path
        )

        trust_data = WinTrustData(
            cbStruct=ctypes.sizeof(WinTrustData),
            dwUIChoice=WTD_UI_NONE,
            fdwRevocationChecks=WTD_REVOKE_NONE,
            dwUnionChoice=WTD_CHOICE_FILE,
            pFile=ctypes.pointer(file_info),
            dwStateAction=WTD_STATEACTION_VERIFY
        )

        result = wintrust.WinVerifyTrust(
            0,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(trust_data)
        )

        if result == 0:
            return "Trusted"
        else:
            if result == -2146762751:  # CERT_E_EXPIRED
                return "Certificate Expired"
            elif result == -2146762748:  # CERT_E_REVOKED
                return "Certificate Revoked"
            elif result == -2146762496:  # TRUST_E_NOSIGNATURE
                return "No Signature"
            elif result == -2146762485:  # TRUST_E_SUBJECT_NOT_TRUSTED
                return "Subject Not Trusted"
            else:
                return f"Untrusted (Error code: {result})"
    except Exception as e:
        print(f"Exception in check_signature for {file_path}: {e}")
        return "Untrusted"


def enrich_process_info(processes):
    for proc in processes:
        try:
            p = psutil.Process(proc['ProcessID'])
            exe_path = p.exe() if p.exe() else "Unknown"
            proc['ExecutablePath'] = exe_path
            proc['SignatureStatus'] = check_signature(
                exe_path) if os.path.exists(exe_path) else "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            print(f"Exception for process {proc['ProcessID']}: {e}")
            proc['ExecutablePath'] = "Unknown"
            proc['SignatureStatus'] = "Unknown"
    return processes


def save_to_json(data, filename):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=2)
        print(f"Data successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving to {filename}: {e}")


def main():
    try:
        processes = get_running_processes()
        processes = enrich_process_info(processes)
        output_directory = "C:/Users/User/Desktop/ProcessInfo"
        os.makedirs(output_directory, exist_ok=True)
        output_path = os.path.join(output_directory, "processes.json")
        save_to_json(processes, output_path)
        print(f"Process information saved to {output_path}")
    except Exception as e:
        print(f"Error in main: {e}")


if __name__ == "__main__":
    main()
