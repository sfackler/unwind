use gimli::{Endianity, Register};
use libc::ucontext_t;

mod x86_64;

pub type NativeArchitecture = x86_64::X86_64;

pub trait Architecture {
    type Registers: Registers + Default;
    type Endianity: Endianity;

    const RA_REGISTER: Register;
    const CFA_REGISTER: Option<Register>;
    const ADDRESS_SIZE: u8;

    fn instruction_pointer(context: &ucontext_t) -> u64;

    fn registers(context: &ucontext_t) -> Self::Registers;
}

pub trait Registers {
    fn set_cfa(&mut self, cfa: u64);

    fn get(&self, register: Register) -> Option<&Option<u64>>;

    fn get_mut(&mut self, register: Register) -> Option<&mut Option<u64>>;
}
