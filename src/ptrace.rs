//! Helper code to use seccomp together with ptrace.

use std::os::unix::process::CommandExt;

use super::*;

pub trait CommandSeccomp {
    /// Run the command with the specified seccomp restrictions.
    fn seccomp(&mut self, ctx: Context) -> &mut Self;
    /// Run the command with the specified seccomp restrictions, and
    /// trace it using ptrace.
    fn ptrace_seccomp(&mut self, ctx: Context) -> &mut Self;
    fn spawn_and_ptrace(&mut self) -> std::io::Result<std::process::Child>;
}

impl CommandSeccomp for std::process::Command {
    fn seccomp(&mut self, ctx: Context) -> &mut Self {
        self.before_exec(move || {
            match ctx.load() {
                Ok(()) => Ok(()),
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other,e)),
            }
        });
        self
    }
    fn ptrace_seccomp(&mut self, ctx: Context) -> &mut Self {
        self.before_exec(move || {
            unsafe {
                libc::ptrace(libc::PTRACE_TRACEME,0,0,0);
            }
            match ctx.load() {
                Ok(()) => Ok(()),
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other,e)),
            }?;
            // The following enables our parent to trace us before we
            // begin with the exec.
            unsafe {
                // libc::kill(libc::getpid(), libc::SIGSTOP);
            }
            Ok(())
        });
        self
    }
    fn spawn_and_ptrace(&mut self) -> std::io::Result<std::process::Child> {
        let ch = self.spawn()?;
        let mut status = 0;
        unsafe {
            //libc::waitpid(ch.id() as i32, &mut status, 0);
            libc::ptrace(libc::PTRACE_SETOPTIONS, ch.id() as i32, 0,
                         libc::PTRACE_O_TRACESECCOMP);
        }
        Ok(ch)
    }
}
