use crate::architecture::{Architecture, Registers};
use gimli::{LittleEndian, Register};
use libc::{
    ucontext_t, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_R8, REG_R9, REG_RAX,
    REG_RBP, REG_RBX, REG_RCX, REG_RDI, REG_RDX, REG_RIP, REG_RSI, REG_RSP,
};

pub enum X86_64 {}

impl Architecture for X86_64 {
    type Registers = X86_64Registers;
    type Endianity = LittleEndian;

    const RA_REGISTER: Register = gimli::X86_64::RA;
    const CFA_REGISTER: Option<Register> = Some(gimli::X86_64::RSP);

    fn instruction_pointer(ctx: &ucontext_t) -> u64 {
        ctx.uc_mcontext.gregs[REG_RIP as usize] as u64
    }

    fn registers(ctx: &ucontext_t) -> Self::Registers {
        X86_64Registers([
            Some(ctx.uc_mcontext.gregs[REG_RAX as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_RDX as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_RCX as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_RBX as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_RSI as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_RDI as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_RBP as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_RSP as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_R8 as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_R9 as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_R10 as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_R11 as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_R12 as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_R13 as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_R14 as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_R15 as usize] as u64),
            Some(ctx.uc_mcontext.gregs[REG_RIP as usize] as u64),
        ])
    }
}

#[derive(Default)]
pub struct X86_64Registers([Option<u64>; 17]);

impl Registers for X86_64Registers {
    fn set_cfa(&mut self, cfa: u64) {
        self.0[gimli::X86_64::RSP.0 as usize] = Some(cfa);
    }

    fn get(&self, register: Register) -> Option<&Option<u64>> {
        self.0.get(register.0 as usize)
    }

    fn get_mut(&mut self, register: Register) -> Option<&mut Option<u64>> {
        self.0.get_mut(register.0 as usize)
    }
}
