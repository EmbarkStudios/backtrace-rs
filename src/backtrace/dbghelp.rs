//! Backtrace strategy for MSVC platforms.
//!
//! This module contains the ability to generate a backtrace on MSVC using one
//! of two possible methods. The `StackWalkEx` function is primarily used if
//! possible, but not all systems have that. Failing that the `StackWalk64`
//! function is used instead. Note that `StackWalkEx` is favored because it
//! handles debuginfo internally and returns inline frame information.
//!
//! Note that all dbghelp support is loaded dynamically, see `src/dbghelp.rs`
//! for more information about that.

#![allow(bad_style)]

use super::super::{dbghelp, windows::*};
use core::ffi::c_void;
use core::mem;
use core::hash::Hash;

impl PartialEq<ADDRESS64> for ADDRESS64 {
    fn eq(&self, other: &ADDRESS64) -> bool {
        self.Offset == other.Offset && self.Segment == other.Segment && self.Mode == other.Mode
    }
}

impl PartialEq<KDHELP64> for KDHELP64 {
    fn eq(&self, other: &KDHELP64) -> bool {
        self.Thread == other.Thread && self.ThCallbackStack == other.ThCallbackStack && self.ThCallbackBStore == other.ThCallbackBStore && self.NextCallback == other.NextCallback && self.FramePointer == other.FramePointer && self.KiCallUserMode == other.KiCallUserMode && self.KeUserCallbackDispatcher == other.KeUserCallbackDispatcher && self.SystemRangeStart == other.SystemRangeStart && self.KiUserExceptionDispatcher == other.KiUserExceptionDispatcher && self.StackBase == other.StackBase && self.StackLimit == other.StackLimit && self.BuildVersion == other.BuildVersion && self.Reserved0 == other.Reserved0 && self.Reserved1 == other.Reserved1
    }
}

impl PartialEq<STACKFRAME_EX> for STACKFRAME_EX {
    fn eq(&self, other: &STACKFRAME_EX) -> bool {
        self.AddrPC == other.AddrPC && self.AddrReturn == other.AddrReturn && self.AddrFrame == other.AddrFrame && self.AddrStack == other.AddrStack && self.AddrBStore == other.AddrBStore && self.FuncTableEntry == other.FuncTableEntry && self.Params == other.Params && self.Far == other.Far && self.Virtual == other.Virtual && self.Reserved == other.Reserved && self.KdHelp == other.KdHelp && self.StackFrameSize == other.StackFrameSize && self.InlineFrameContext == other.InlineFrameContext
    }
}

impl Hash for KDHELP64 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.Thread.hash(state);
        self.ThCallbackStack.hash(state);
        self.ThCallbackBStore.hash(state);
        self.NextCallback.hash(state);
        self.FramePointer.hash(state);
        self.KiCallUserMode.hash(state);
        self.KeUserCallbackDispatcher.hash(state);
        self.SystemRangeStart.hash(state);
        self.KiUserExceptionDispatcher.hash(state);
        self.StackBase.hash(state);
        self.StackLimit.hash(state);
        self.BuildVersion.hash(state);
        self.Reserved0.hash(state);
        self.Reserved1.hash(state);
    }
}

impl Hash for STACKFRAME_EX {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.AddrPC.hash(state);
        self.AddrReturn.hash(state);
        self.AddrFrame.hash(state);
        self.AddrStack.hash(state);
        self.AddrBStore.hash(state);
        self.FuncTableEntry.hash(state);
        self.Params.hash(state);
        self.Far.hash(state);
        self.Virtual.hash(state);
        self.Reserved.hash(state);
        self.KdHelp.hash(state);
        self.StackFrameSize.hash(state);
        self.InlineFrameContext.hash(state);
    }
}

impl PartialEq<STACKFRAME64> for STACKFRAME64 {
    fn eq(&self, other: &STACKFRAME64) -> bool {
        self.AddrPC == other.AddrPC && self.AddrReturn == other.AddrReturn && self.AddrFrame == other.AddrFrame && self.AddrStack == other.AddrStack && self.AddrBStore == other.AddrBStore && self.FuncTableEntry == other.FuncTableEntry && self.Params == other.Params && self.Far == other.Far && self.Virtual == other.Virtual && self.Reserved == other.Reserved && self.KdHelp == other.KdHelp
    }
}

impl Hash for ADDRESS64 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.Offset.hash(state);
        self.Segment.hash(state);
        self.Mode.hash(state);
    }
}

impl Hash for STACKFRAME64 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.AddrPC.hash(state);
        self.AddrReturn.hash(state);
        self.AddrFrame.hash(state);
        self.AddrStack.hash(state);
        self.AddrBStore.hash(state);
        self.FuncTableEntry.hash(state);
        self.Params.hash(state);
        self.Far.hash(state);
        self.Virtual.hash(state);
        self.Reserved.hash(state);
        //self.KdHelp.hash(state);
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum StackFrame {
    New(STACKFRAME_EX),
    Old(STACKFRAME64),
}

impl Hash for StackFrame {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
    }
}

#[derive(Clone, Copy, PartialEq, Hash)]
pub struct Frame {
    pub(crate) stack_frame: StackFrame,
    base_address: *mut c_void,
}

// we're just sending around raw pointers and reading them, never interpreting
// them so this should be safe to both send and share across threads.
unsafe impl Send for Frame {}
unsafe impl Sync for Frame {}

impl Frame {
    pub fn ip(&self) -> *mut c_void {
        self.addr_pc().Offset as *mut _
    }

    pub fn sp(&self) -> *mut c_void {
        self.addr_stack().Offset as *mut _
    }

    pub fn symbol_address(&self) -> *mut c_void {
        self.ip()
    }

    pub fn module_base_address(&self) -> Option<*mut c_void> {
        Some(self.base_address)
    }

    fn addr_pc(&self) -> &ADDRESS64 {
        match self.stack_frame {
            StackFrame::New(ref new) => &new.AddrPC,
            StackFrame::Old(ref old) => &old.AddrPC,
        }
    }

    fn addr_pc_mut(&mut self) -> &mut ADDRESS64 {
        match self.stack_frame {
            StackFrame::New(ref mut new) => &mut new.AddrPC,
            StackFrame::Old(ref mut old) => &mut old.AddrPC,
        }
    }

    fn addr_frame_mut(&mut self) -> &mut ADDRESS64 {
        match self.stack_frame {
            StackFrame::New(ref mut new) => &mut new.AddrFrame,
            StackFrame::Old(ref mut old) => &mut old.AddrFrame,
        }
    }

    fn addr_stack(&self) -> &ADDRESS64 {
        match self.stack_frame {
            StackFrame::New(ref new) => &new.AddrStack,
            StackFrame::Old(ref old) => &old.AddrStack,
        }
    }

    fn addr_stack_mut(&mut self) -> &mut ADDRESS64 {
        match self.stack_frame {
            StackFrame::New(ref mut new) => &mut new.AddrStack,
            StackFrame::Old(ref mut old) => &mut old.AddrStack,
        }
    }
}

#[repr(C, align(16))] // required by `CONTEXT`, is a FIXME in winapi right now
struct MyContext(CONTEXT);

#[inline(always)]
pub unsafe fn trace(cb: &mut dyn FnMut(&super::Frame) -> bool) {
    // Allocate necessary structures for doing the stack walk
    let process = GetCurrentProcess();
    let thread = GetCurrentThread();

    let mut context = mem::zeroed::<MyContext>();
    RtlCaptureContext(&mut context.0);

    // Ensure this process's symbols are initialized
    let dbghelp = match dbghelp::init() {
        Ok(dbghelp) => dbghelp,
        Err(()) => return, // oh well...
    };

    // On x86_64 and ARM64 we opt to not use the default `Sym*` functions from
    // dbghelp for getting the function table and module base. Instead we use
    // the `RtlLookupFunctionEntry` function in kernel32 which will account for
    // JIT compiler frames as well. These should be equivalent, but using
    // `Rtl*` allows us to backtrace through JIT frames.
    //
    // Note that `RtlLookupFunctionEntry` only works for in-process backtraces,
    // but that's all we support anyway, so it all lines up well.
    cfg_if::cfg_if! {
        if #[cfg(target_pointer_width = "64")] {
            use core::ptr;

            unsafe extern "system" fn function_table_access(_process: HANDLE, addr: DWORD64) -> PVOID {
                let mut base = 0;
                RtlLookupFunctionEntry(addr, &mut base, ptr::null_mut()).cast()
            }

            unsafe extern "system" fn get_module_base(_process: HANDLE, addr: DWORD64) -> DWORD64 {
                let mut base = 0;
                RtlLookupFunctionEntry(addr, &mut base, ptr::null_mut());
                base
            }
        } else {
            let function_table_access = dbghelp.SymFunctionTableAccess64();
            let get_module_base = dbghelp.SymGetModuleBase64();
        }
    }

    let process_handle = GetCurrentProcess();

    // Attempt to use `StackWalkEx` if we can, but fall back to `StackWalk64`
    // since it's in theory supported on more systems.
    match (*dbghelp.dbghelp()).StackWalkEx() {
        Some(StackWalkEx) => {
            let mut frame = super::Frame {
                inner: Frame {
                    stack_frame: StackFrame::New(mem::zeroed()),
                    base_address: 0 as _,
                },
            };
            let image = init_frame(&mut frame.inner, &context.0);
            let frame_ptr = match &mut frame.inner.stack_frame {
                StackFrame::New(ptr) => ptr as *mut STACKFRAME_EX,
                _ => unreachable!(),
            };

            while StackWalkEx(
                image as DWORD,
                process,
                thread,
                frame_ptr,
                &mut context.0 as *mut CONTEXT as *mut _,
                None,
                Some(function_table_access),
                Some(get_module_base),
                None,
                0,
            ) == TRUE
            {
                frame.inner.base_address = get_module_base(process_handle, frame.ip() as _) as _;

                if !cb(&frame) {
                    break;
                }
            }
        }
        None => {
            let mut frame = super::Frame {
                inner: Frame {
                    stack_frame: StackFrame::Old(mem::zeroed()),
                    base_address: 0 as _,
                },
            };
            let image = init_frame(&mut frame.inner, &context.0);
            let frame_ptr = match &mut frame.inner.stack_frame {
                StackFrame::Old(ptr) => ptr as *mut STACKFRAME64,
                _ => unreachable!(),
            };

            while dbghelp.StackWalk64()(
                image as DWORD,
                process,
                thread,
                frame_ptr,
                &mut context.0 as *mut CONTEXT as *mut _,
                None,
                Some(function_table_access),
                Some(get_module_base),
                None,
            ) == TRUE
            {
                frame.inner.base_address = get_module_base(process_handle, frame.ip() as _) as _;

                if !cb(&frame) {
                    break;
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn init_frame(frame: &mut Frame, ctx: &CONTEXT) -> WORD {
    frame.addr_pc_mut().Offset = ctx.Rip as u64;
    frame.addr_pc_mut().Mode = AddrModeFlat;
    frame.addr_stack_mut().Offset = ctx.Rsp as u64;
    frame.addr_stack_mut().Mode = AddrModeFlat;
    frame.addr_frame_mut().Offset = ctx.Rbp as u64;
    frame.addr_frame_mut().Mode = AddrModeFlat;

    IMAGE_FILE_MACHINE_AMD64
}

#[cfg(target_arch = "x86")]
fn init_frame(frame: &mut Frame, ctx: &CONTEXT) -> WORD {
    frame.addr_pc_mut().Offset = ctx.Eip as u64;
    frame.addr_pc_mut().Mode = AddrModeFlat;
    frame.addr_stack_mut().Offset = ctx.Esp as u64;
    frame.addr_stack_mut().Mode = AddrModeFlat;
    frame.addr_frame_mut().Offset = ctx.Ebp as u64;
    frame.addr_frame_mut().Mode = AddrModeFlat;

    IMAGE_FILE_MACHINE_I386
}

#[cfg(target_arch = "aarch64")]
fn init_frame(frame: &mut Frame, ctx: &CONTEXT) -> WORD {
    frame.addr_pc_mut().Offset = ctx.Pc as u64;
    frame.addr_pc_mut().Mode = AddrModeFlat;
    frame.addr_stack_mut().Offset = ctx.Sp as u64;
    frame.addr_stack_mut().Mode = AddrModeFlat;
    unsafe {
        frame.addr_frame_mut().Offset = ctx.u.s().Fp as u64;
    }
    frame.addr_frame_mut().Mode = AddrModeFlat;
    IMAGE_FILE_MACHINE_ARM64
}

#[cfg(target_arch = "arm")]
fn init_frame(frame: &mut Frame, ctx: &CONTEXT) -> WORD {
    frame.addr_pc_mut().Offset = ctx.Pc as u64;
    frame.addr_pc_mut().Mode = AddrModeFlat;
    frame.addr_stack_mut().Offset = ctx.Sp as u64;
    frame.addr_stack_mut().Mode = AddrModeFlat;
    unsafe {
        frame.addr_frame_mut().Offset = ctx.R11 as u64;
    }
    frame.addr_frame_mut().Mode = AddrModeFlat;
    IMAGE_FILE_MACHINE_ARMNT
}
