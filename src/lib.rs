use crate::architecture::{Architecture, NativeArchitecture, Registers};
use core::slice;
use gimli::{
    BaseAddresses, CfaRule, EhFrame, EhFrameHdr, EhFrameOffset, NativeEndian, Pointer,
    RegisterRule, UnwindContext, UnwindSection,
};
use libc::{
    c_int, c_void, dl_iterate_phdr, dl_phdr_info, getcontext, Elf64_Addr, Elf64_Phdr,
    PT_GNU_EH_FRAME, PT_LOAD,
};
use std::mem::{self, MaybeUninit};

mod architecture;

struct Sections {
    text: &'static [u8],
    eh_frame_hdr: &'static [u8],
    eh_frame: &'static [u8],
}

struct CallbackData {
    addr: usize,
    sections: Option<Sections>,
}

unsafe extern "C" fn callback(info: *mut dl_phdr_info, _size: usize, data: *mut c_void) -> c_int {
    let info = &*info;
    let data = &mut *(data.cast::<CallbackData>());

    let phdrs = slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);

    let text = match phdrs
        .iter()
        .filter(|hdr| hdr.p_type == PT_LOAD)
        .find(|hdr| contains_addr(data.addr, info.dlpi_addr, hdr))
        .map(|hdr| section_slice(info.dlpi_addr, hdr))
    {
        Some(text) => text,
        None => return 0,
    };

    let eh_frame_hdr = match phdrs
        .iter()
        .find(|hdr| hdr.p_type == PT_GNU_EH_FRAME)
        .map(|hdr| section_slice(info.dlpi_addr, hdr))
    {
        Some(eh_frame_hdr) => eh_frame_hdr,
        None => return 1,
    };

    let bases = BaseAddresses::default().set_eh_frame_hdr(eh_frame_hdr.as_ptr() as u64);

    let parsed_eh_frame_hdr = match EhFrameHdr::new(eh_frame_hdr, NativeEndian)
        .parse(&bases, mem::size_of::<usize>() as u8)
    {
        Ok(parsed_eh_frame_hdr) => parsed_eh_frame_hdr,
        Err(_) => return 1,
    };
    let eh_frame_base = match parsed_eh_frame_hdr.eh_frame_ptr() {
        Pointer::Direct(addr) => addr as usize,
        Pointer::Indirect(p) => *(p as *const usize),
    };

    let eh_frame = match phdrs
        .iter()
        .find(|hdr| contains_addr(eh_frame_base, info.dlpi_addr, hdr))
        .map(|hdr| section_slice(info.dlpi_addr, hdr))
    {
        Some(eh_frame) => eh_frame,
        None => return 1,
    };

    data.sections = Some(Sections {
        text,
        eh_frame_hdr,
        eh_frame,
    });

    1
}

fn contains_addr(addr: usize, base: Elf64_Addr, phdr: &Elf64_Phdr) -> bool {
    let start = base + phdr.p_vaddr;
    let end = start + phdr.p_memsz;
    (start as usize..end as usize).contains(&addr)
}

unsafe fn section_slice(base: Elf64_Addr, phdr: &Elf64_Phdr) -> &'static [u8] {
    slice::from_raw_parts((base + phdr.p_vaddr) as *const u8, phdr.p_memsz as usize)
}

fn find_sections(addr: usize) -> Option<Sections> {
    let mut data = CallbackData {
        addr,
        sections: None,
    };

    unsafe {
        dl_iterate_phdr(Some(callback), &mut data as *mut _ as *mut c_void);
    }

    data.sections
}

pub fn trace() {
    let mut ctx = MaybeUninit::uninit();
    let ctx = unsafe {
        getcontext(ctx.as_mut_ptr());
        ctx.assume_init_ref()
    };

    let mut unwind_cxt = UnwindContext::new();

    let mut registers = NativeArchitecture::registers(&ctx);
    let mut next_ip = Some(NativeArchitecture::instruction_pointer(&ctx));

    while let Some(ip) = next_ip {
        let sections = match find_sections(ip as usize) {
            Some(sections) => sections,
            None => break,
        };

        let mut ran = false;
        backtrace::resolve(ip as *mut _, |symbol| {
            if let Some(name) = symbol.name() {
                ran = true;
                println!("{ip:#016x}: {name}")
            }
        });
        if !ran {
            println!("{ip:#016x}: ???");
        }

        let bases = BaseAddresses::default()
            .set_text(sections.text.as_ptr() as u64)
            .set_eh_frame(sections.eh_frame.as_ptr() as u64)
            .set_eh_frame_hdr(sections.eh_frame_hdr.as_ptr() as u64);

        let eh_frame_hdr = match EhFrameHdr::new(sections.eh_frame_hdr, NativeEndian)
            .parse(&bases, mem::size_of::<usize>() as u8)
        {
            Ok(eh_frame_hdr) => eh_frame_hdr,
            Err(e) => {
                println!("eh_frame_hdr parse {e}");
                break;
            }
        };

        let table = match eh_frame_hdr.table() {
            Some(table) => table,
            None => {
                println!("no eh_frame_hdr table");
                break;
            }
        };

        // FIXME linear search if table is absent
        let ptr = match table.lookup(ip, &bases) {
            Ok(ptr) => ptr,
            Err(e) => {
                println!("table lookup: {e}");
                break;
            }
        };
        let ptr = match ptr {
            Pointer::Direct(x) => x,
            Pointer::Indirect(a) => unsafe { *(a as *const u64) },
        };
        let offset = EhFrameOffset(ptr as usize - sections.eh_frame.as_ptr() as usize);

        let eh_frame = EhFrame::new(sections.eh_frame, NativeEndian);

        let entry = match eh_frame.fde_from_offset(&bases, offset, EhFrame::cie_from_offset) {
            Ok(entry) => entry,
            Err(e) => {
                println!("fde_from_offset: {e}");
                break;
            }
        };

        let row = match entry.unwind_info_for_address(&eh_frame, &bases, &mut unwind_cxt, ip) {
            Ok(row) => row,
            Err(e) => {
                println!("FDE unwind_info_for_address: {e}");
                break;
            }
        };

        let cfa = match row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => registers
                .get(*register)
                .copied()
                .unwrap_or(None)
                .map(|v| v.wrapping_add(*offset as u64))
                .unwrap(),
            CfaRule::Expression(_) => todo!(),
        };

        let mut new_registers = <NativeArchitecture as Architecture>::Registers::default();
        for (register, rule) in row.registers() {
            let target = match new_registers.get_mut(*register) {
                Some(target) => target,
                None => continue,
            };

            *target = match rule {
                RegisterRule::Undefined => None,
                RegisterRule::SameValue => registers.get(*register).copied().unwrap_or(None),
                RegisterRule::Offset(v) => {
                    Some(unsafe { *(cfa.wrapping_add(*v as u64) as *const u64) })
                }
                RegisterRule::ValOffset(v) => Some(cfa.wrapping_add(*v as u64)),
                RegisterRule::Register(r) => registers.get(*r).copied().unwrap_or(None),
                RegisterRule::Expression(_) => todo!(),
                RegisterRule::ValExpression(_) => todo!(),
                RegisterRule::Architectural => todo!(),
            };
        }
        new_registers.set_cfa(cfa);

        registers = new_registers;
        next_ip = registers
            .get(entry.cie().return_address_register())
            .copied()
            .unwrap_or(None)
            .map(|i| i - 1);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        trace();
    }
}
