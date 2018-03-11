//! This crate is based on [seccomp_sys](https://crates.io/crates/seccomp-sys) and provides
//! a higher level wrapper for [libseccomp](https://github.com/seccomp/libseccomp).
//!
//!
//! Example usage:
//!
//! ```rust,no_run
//!extern crate seccomp_droundy;
//!extern crate libc;
//!
//!use seccomp_droundy::*;
//!
//!fn main() {
//!		let mut ctx = Context::default(Action::Allow).unwrap();
//!		let rule = Rule::new(105 /* setuid on x86_64 */,
//!			Compare::arg(0)
//! 			    .with(1000)
//! 				.using(Op::Eq)
//! 				.build().unwrap(),
//!			Action::Errno(libc::EPERM) /* return EPERM */
//!		);
//!		ctx.add_rule(rule).unwrap();
//!		ctx.load().unwrap();
//!		let ret = unsafe { libc::setuid(1000) };
//!		println!("ret = {}, uid = {}", ret, unsafe { libc::getuid() });
//!}
//!
//!


extern crate seccomp_droundy_sys;
extern crate libc;

use seccomp_droundy_sys::*;
use std::error::Error;
use std::fmt;
use std::convert::Into;
use seccomp_droundy_sys::scmp_compare::*;

pub type Cmp = scmp_arg_cmp;
#[derive(Debug,Copy,Clone,Eq,PartialEq)]
pub struct Arch(u32);

pub const ARCH_NATIVE: Arch = Arch(scmp_arch::SCMP_ARCH_NATIVE as u32);
pub const ARCH_X86: Arch = Arch(scmp_arch::SCMP_ARCH_X86 as u32);
pub const ARCH_X86_64: Arch = Arch(scmp_arch::SCMP_ARCH_X86_64 as u32);
pub const ARCH_X32: Arch = Arch(scmp_arch::SCMP_ARCH_X32 as u32);

/// Comparison operators
#[derive(Debug,Clone,Copy)]
pub enum Op {
	/// not equal
	Ne,
	/// less than
	Lt,
	/// less than or equal
	Le,
	/// equal
	Eq,
	/// greater than or equal
	Ge,
	/// greater than
	Gt,
	/// masked equality
	MaskedEq,
}

impl Into<scmp_compare> for Op {
	fn into(self) -> scmp_compare {
		match self {
			Op::Ne => SCMP_CMP_NE,
			Op::Lt => SCMP_CMP_LT,
			Op::Le => SCMP_CMP_LE,
			Op::Eq => SCMP_CMP_EQ,
			Op::Ge => SCMP_CMP_GE,
			Op::Gt => SCMP_CMP_GT,
			Op::MaskedEq => SCMP_CMP_MASKED_EQ,
		}
	}
}

/// Seccomp actions
#[derive(Debug,Clone,Copy)]
pub enum Action {
	/// Allow the syscall to be executed
	Allow,
	/// Kill the process
	Kill,
	/// Throw a SIGSYS signal
	Trap,
	/// Return the specified error code
	Errno(i32),
	/// Notify a tracing process with the specified value
	Trace(u32),
}

impl Into<libc::uint32_t> for Action {
	fn into(self) -> libc::uint32_t {
		match self {
			Action::Allow => SCMP_ACT_ALLOW,
			Action::Kill => SCMP_ACT_KILL,
			Action::Trap => SCMP_ACT_TRAP,
			Action::Errno(x) => SCMP_ACT_ERRNO(x as u32),
			Action::Trace(x) => SCMP_ACT_TRACE(x),
		}
	}
}

/// A macro to ergonomically express comparisons using ordinary
/// comparison operators.
///
/// # Example
///
/// ```
/// #[macro_use]
/// extern crate seccomp_droundy;
/// use seccomp_droundy::*;
/// use seccomp_droundy as seccomp;
/// fn main() {
///	  let mut ctx = seccomp::Context::default(Action::Allow).unwrap();
///	  let rule = seccomp::Rule::new(105, scmp_cmp!( Arg(0) == 1000 ),
///                             	  seccomp::Action::Errno(5) /* return an error */
///	  );
/// }
/// ```
#[macro_export]
macro_rules! scmp_cmp {
    (Arg($arg:expr) != $value:expr) => {{
        Cmp { arg: $arg, op: $crate::Op::Ne.into(), datum_a: $value, datum_b: 0 }
    }};
    (Arg($arg:expr) < $value:expr) => {{
        Cmp { arg: $arg, op: $crate::Op::Lt.into(), datum_a: $value, datum_b: 0 }
    }};
    (Arg($arg:expr) <= $value:expr) => {{
        Cmp { arg: $arg, op: $crate::Op::Le.into(), datum_a: $value, datum_b: 0 }
    }};
    (Arg($arg:expr) == $value:expr) => {{
        Cmp { arg: $arg, op: $crate::Op::Eq.into(), datum_a: $value, datum_b: 0 }
    }};
    (Arg($arg:expr) >= $value:expr) => {{
        Cmp { arg: $arg, op: $crate::Op::Ge.into(), datum_a: $value, datum_b: 0 }
    }};
    (Arg($arg:expr) > $value:expr) => {{
        Cmp { arg: $arg, op: $crate::Op::Gt.into(), datum_a: $value, datum_b: 0 }
    }};
}

/// Comparison definition builder
pub struct Compare {
	arg: libc::c_uint,
	op: Option<Op>,
	datum_a: Option<scmp_datum_t>,
	datum_b: Option<scmp_datum_t>,
}

impl Compare {
	/// argument number, starting at 0
	pub fn arg(arg_num: u32) -> Self {
		Compare { arg: arg_num as libc::c_uint, op: None, datum_a: None, datum_b: None }
	}

	/// Comparison operator
	pub fn using(mut self, op: Op) -> Self {
		self.op = Some(op);
		self
	}

	/// Datum to compare with
	pub fn with(mut self, datum: u64) -> Self {
		self.datum_a = Some(datum);
		self
	}

	/// Second datum
	pub fn and(mut self, datum: u64) -> Self {
		self.datum_b = Some(datum);
		self
	}

	/// build comparison definition
	pub fn build(self) -> Option<Cmp> {
		if self.op.is_some() && self.datum_a.is_some() {
			Some(Cmp {
				 arg: self.arg,
				 op: self.op.unwrap().into(),
				 datum_a: self.datum_a.unwrap(),
				 datum_b: self.datum_b.unwrap_or(0)
			 })
		} else {
			None
		}
	}
}

/// Seccomp rule
#[derive(Debug)]
pub struct Rule {
	action: Action,
	syscall_nr: usize,
	comparators: Vec<Cmp>,
}

#[allow(non_camel_case_types)]
#[derive(Debug,Clone,Copy)]
pub enum Syscall {
    read,
    write,
    open,
    close,
    stat,
    stat64,
    fstat,
    lstat,
    lstat64,
    poll,
    lseek,
    mmap,
    mprotect,
    munmap,
    brk,
    rt_sigaction,
    rt_sigprocmask,
    rt_sigreturn,
    ioctl,
    pread64,
    pwrite64,
    readv,
    writev,
    access,
    pipe,
    select,
    sched_yield,
    mremap,
    msync,
    mincore,
    madvise,
    shmget,
    shmat,
    shmctl,
    dup,
    dup2,
    pause,
    nanosleep,
    getitimer,
    alarm,
    setitimer,
    getpid,
    sendfile,
    socket,
    connect,
    accept,
    sendto,
    recvfrom,
    sendmsg,
    recvmsg,
    shutdown,
    bind,
    listen,
    getsockname,
    getpeername,
    socketpair,
    setsockopt,
    getsockopt,
    clone,
    fork,
    vfork,
    execve,
    exit,
    wait4,
    kill,
    uname,
    semget,
    semop,
    semctl,
    shmdt,
    msgget,
    msgsnd,
    msgrcv,
    msgctl,
    fcntl,
    flock,
    fsync,
    fdatasync,
    truncate,
    ftruncate,
    getdents,
    getcwd,
    chdir,
    fchdir,
    rename,
    mkdir,
    rmdir,
    creat,
    link,
    unlink,
    symlink,
    readlink,
    chmod,
    fchmod,
    chown,
    fchown,
    lchown,
    umask,
    gettimeofday,
    getrlimit,
    getrusage,
    sysinfo,
    times,
    ptrace,
    getuid,
    syslog,
    getgid,
    setuid,
    setgid,
    geteuid,
    getegid,
    setpgid,
    getppid,
    getpgrp,
    setsid,
    setreuid,
    setregid,
    getgroups,
    setgroups,
    setresuid,
    getresuid,
    setresgid,
    getresgid,
    getpgid,
    setfsuid,
    setfsgid,
    getsid,
    capget,
    capset,
    rt_sigpending,
    rt_sigtimedwait,
    rt_sigqueueinfo,
    rt_sigsuspend,
    sigaltstack,
    utime,
    mknod,
    uselib,
    personality,
    ustat,
    statfs,
    fstatfs,
    sysfs,
    getpriority,
    setpriority,
    sched_setparam,
    sched_getparam,
    sched_setscheduler,
    sched_getscheduler,
    sched_get_priority_max,
    sched_get_priority_min,
    sched_rr_get_interval,
    mlock,
    munlock,
    mlockall,
    munlockall,
    vhangup,
    modify_ldt,
    pivot_root,
    _sysctl,
    prctl,
    arch_prctl,
    adjtimex,
    setrlimit,
    chroot,
    sync,
    acct,
    settimeofday,
    mount,
    umount2,
    swapon,
    swapoff,
    reboot,
    sethostname,
    setdomainname,
    iopl,
    ioperm,
    create_module,
    init_module,
    delete_module,
    get_kernel_syms,
    query_module,
    quotactl,
    nfsservctl,
    getpmsg,
    putpmsg,
    afs_syscall,
    tuxcall,
    security,
    gettid,
    readahead,
    setxattr,
    lsetxattr,
    fsetxattr,
    getxattr,
    lgetxattr,
    fgetxattr,
    listxattr,
    llistxattr,
    flistxattr,
    removexattr,
    lremovexattr,
    fremovexattr,
    tkill,
    time,
    futex,
    sched_setaffinity,
    sched_getaffinity,
    set_thread_area,
    io_setup,
    io_destroy,
    io_getevents,
    io_submit,
    io_cancel,
    get_thread_area,
    lookup_dcookie,
    epoll_create,
    epoll_ctl_old,
    epoll_wait_old,
    remap_file_pages,
    getdents64,
    set_tid_address,
    restart_syscall,
    semtimedop,
    fadvise64,
    timer_create,
    timer_settime,
    timer_gettime,
    timer_getoverrun,
    timer_delete,
    clock_settime,
    clock_gettime,
    clock_getres,
    clock_nanosleep,
    exit_group,
    epoll_wait,
    epoll_ctl,
    tgkill,
    utimes,
    vserver,
    mbind,
    set_mempolicy,
    get_mempolicy,
    mq_open,
    mq_unlink,
    mq_timedsend,
    mq_timedreceive,
    mq_notify,
    mq_getsetattr,
    kexec_load,
    waitid,
    add_key,
    request_key,
    keyctl,
    ioprio_set,
    ioprio_get,
    inotify_init,
    inotify_add_watch,
    inotify_rm_watch,
    migrate_pages,
    openat,
    mkdirat,
    mknodat,
    fchownat,
    futimesat,
    newfstatat,
    unlinkat,
    renameat,
    linkat,
    symlinkat,
    readlinkat,
    fchmodat,
    faccessat,
    pselect6,
    ppoll,
    unshare,
    set_robust_list,
    get_robust_list,
    splice,
    tee,
    sync_file_range,
    vmsplice,
    move_pages,
    utimensat,
    epoll_pwait,
    signalfd,
    timerfd_create,
    eventfd,
    fallocate,
    timerfd_settime,
    timerfd_gettime,
    accept4,
    signalfd4,
    eventfd2,
    epoll_create1,
    dup3,
    pipe2,
    inotify_init1,
    preadv,
    pwritev,
    rt_tgsigqueueinfo,
    perf_event_open,
    recvmmsg,
    fanotify_init,
    fanotify_mark,
    prlimit64,
    name_to_handle_at,
    open_by_handle_at,
    clock_adjtime,
    syncfs,
    sendmmsg,
    setns,
    getcpu,
    process_vm_readv,
    process_vm_writev,
    kcmp,
    finit_module,
    sched_setattr,
    sched_getattr,
    renameat2,
    seccomp,
    getrandom,
    memfd_create,
    kexec_file_load,
    bpf,
    execveat,
    userfaultfd,
    membarrier,
    mlock2,
    copy_file_range,
    preadv2,
    pwritev2,
    xstat,
}

fn syscall_name(s: Syscall) -> &'static str {
    match s {
        Syscall::read => "read",
        Syscall::write => "write",
        Syscall::open => "open",
        Syscall::close => "close",
        Syscall::stat => "stat",
        Syscall::stat64 => "stat64",
        Syscall::fstat => "fstat",
        Syscall::lstat => "lstat",
        Syscall::lstat64 => "lstat64",
        Syscall::poll => "poll",
        Syscall::lseek => "lseek",
        Syscall::mmap => "mmap",
        Syscall::mprotect => "mprotect",
        Syscall::munmap => "munmap",
        Syscall::brk => "brk",
        Syscall::rt_sigaction => "rt_sigaction",
        Syscall::rt_sigprocmask => "rt_sigprocmask",
        Syscall::rt_sigreturn => "rt_sigreturn",
        Syscall::ioctl => "ioctl",
        Syscall::pread64 => "pread64",
        Syscall::pwrite64 => "pwrite64",
        Syscall::readv => "readv",
        Syscall::writev => "writev",
        Syscall::access => "access",
        Syscall::pipe => "pipe",
        Syscall::select => "select",
        Syscall::sched_yield => "sched_yield",
        Syscall::mremap => "mremap",
        Syscall::msync => "msync",
        Syscall::mincore => "mincore",
        Syscall::madvise => "madvise",
        Syscall::shmget => "shmget",
        Syscall::shmat => "shmat",
        Syscall::shmctl => "shmctl",
        Syscall::dup => "dup",
        Syscall::dup2 => "dup2",
        Syscall::pause => "pause",
        Syscall::nanosleep => "nanosleep",
        Syscall::getitimer => "getitimer",
        Syscall::alarm => "alarm",
        Syscall::setitimer => "setitimer",
        Syscall::getpid => "getpid",
        Syscall::sendfile => "sendfile",
        Syscall::socket => "socket",
        Syscall::connect => "connect",
        Syscall::accept => "accept",
        Syscall::sendto => "sendto",
        Syscall::recvfrom => "recvfrom",
        Syscall::sendmsg => "sendmsg",
        Syscall::recvmsg => "recvmsg",
        Syscall::shutdown => "shutdown",
        Syscall::bind => "bind",
        Syscall::listen => "listen",
        Syscall::getsockname => "getsockname",
        Syscall::getpeername => "getpeername",
        Syscall::socketpair => "socketpair",
        Syscall::setsockopt => "setsockopt",
        Syscall::getsockopt => "getsockopt",
        Syscall::clone => "clone",
        Syscall::fork => "fork",
        Syscall::vfork => "vfork",
        Syscall::execve => "execve",
        Syscall::exit => "exit",
        Syscall::wait4 => "wait4",
        Syscall::kill => "kill",
        Syscall::uname => "uname",
        Syscall::semget => "semget",
        Syscall::semop => "semop",
        Syscall::semctl => "semctl",
        Syscall::shmdt => "shmdt",
        Syscall::msgget => "msgget",
        Syscall::msgsnd => "msgsnd",
        Syscall::msgrcv => "msgrcv",
        Syscall::msgctl => "msgctl",
        Syscall::fcntl => "fcntl",
        Syscall::flock => "flock",
        Syscall::fsync => "fsync",
        Syscall::fdatasync => "fdatasync",
        Syscall::truncate => "truncate",
        Syscall::ftruncate => "ftruncate",
        Syscall::getdents => "getdents",
        Syscall::getcwd => "getcwd",
        Syscall::chdir => "chdir",
        Syscall::fchdir => "fchdir",
        Syscall::rename => "rename",
        Syscall::mkdir => "mkdir",
        Syscall::rmdir => "rmdir",
        Syscall::creat => "creat",
        Syscall::link => "link",
        Syscall::unlink => "unlink",
        Syscall::symlink => "symlink",
        Syscall::readlink => "readlink",
        Syscall::chmod => "chmod",
        Syscall::fchmod => "fchmod",
        Syscall::chown => "chown",
        Syscall::fchown => "fchown",
        Syscall::lchown => "lchown",
        Syscall::umask => "umask",
        Syscall::gettimeofday => "gettimeofday",
        Syscall::getrlimit => "getrlimit",
        Syscall::getrusage => "getrusage",
        Syscall::sysinfo => "sysinfo",
        Syscall::times => "times",
        Syscall::ptrace => "ptrace",
        Syscall::getuid => "getuid",
        Syscall::syslog => "syslog",
        Syscall::getgid => "getgid",
        Syscall::setuid => "setuid",
        Syscall::setgid => "setgid",
        Syscall::geteuid => "geteuid",
        Syscall::getegid => "getegid",
        Syscall::setpgid => "setpgid",
        Syscall::getppid => "getppid",
        Syscall::getpgrp => "getpgrp",
        Syscall::setsid => "setsid",
        Syscall::setreuid => "setreuid",
        Syscall::setregid => "setregid",
        Syscall::getgroups => "getgroups",
        Syscall::setgroups => "setgroups",
        Syscall::setresuid => "setresuid",
        Syscall::getresuid => "getresuid",
        Syscall::setresgid => "setresgid",
        Syscall::getresgid => "getresgid",
        Syscall::getpgid => "getpgid",
        Syscall::setfsuid => "setfsuid",
        Syscall::setfsgid => "setfsgid",
        Syscall::getsid => "getsid",
        Syscall::capget => "capget",
        Syscall::capset => "capset",
        Syscall::rt_sigpending => "rt_sigpending",
        Syscall::rt_sigtimedwait => "rt_sigtimedwait",
        Syscall::rt_sigqueueinfo => "rt_sigqueueinfo",
        Syscall::rt_sigsuspend => "rt_sigsuspend",
        Syscall::sigaltstack => "sigaltstack",
        Syscall::utime => "utime",
        Syscall::mknod => "mknod",
        Syscall::uselib => "uselib",
        Syscall::personality => "personality",
        Syscall::ustat => "ustat",
        Syscall::statfs => "statfs",
        Syscall::fstatfs => "fstatfs",
        Syscall::sysfs => "sysfs",
        Syscall::getpriority => "getpriority",
        Syscall::setpriority => "setpriority",
        Syscall::sched_setparam => "sched_setparam",
        Syscall::sched_getparam => "sched_getparam",
        Syscall::sched_setscheduler => "sched_setscheduler",
        Syscall::sched_getscheduler => "sched_getscheduler",
        Syscall::sched_get_priority_max => "sched_get_priority_max",
        Syscall::sched_get_priority_min => "sched_get_priority_min",
        Syscall::sched_rr_get_interval => "sched_rr_get_interval",
        Syscall::mlock => "mlock",
        Syscall::munlock => "munlock",
        Syscall::mlockall => "mlockall",
        Syscall::munlockall => "munlockall",
        Syscall::vhangup => "vhangup",
        Syscall::modify_ldt => "modify_ldt",
        Syscall::pivot_root => "pivot_root",
        Syscall::_sysctl => "_sysctl",
        Syscall::prctl => "prctl",
        Syscall::arch_prctl => "arch_prctl",
        Syscall::adjtimex => "adjtimex",
        Syscall::setrlimit => "setrlimit",
        Syscall::chroot => "chroot",
        Syscall::sync => "sync",
        Syscall::acct => "acct",
        Syscall::settimeofday => "settimeofday",
        Syscall::mount => "mount",
        Syscall::umount2 => "umount2",
        Syscall::swapon => "swapon",
        Syscall::swapoff => "swapoff",
        Syscall::reboot => "reboot",
        Syscall::sethostname => "sethostname",
        Syscall::setdomainname => "setdomainname",
        Syscall::iopl => "iopl",
        Syscall::ioperm => "ioperm",
        Syscall::create_module => "create_module",
        Syscall::init_module => "init_module",
        Syscall::delete_module => "delete_module",
        Syscall::get_kernel_syms => "get_kernel_syms",
        Syscall::query_module => "query_module",
        Syscall::quotactl => "quotactl",
        Syscall::nfsservctl => "nfsservctl",
        Syscall::getpmsg => "getpmsg",
        Syscall::putpmsg => "putpmsg",
        Syscall::afs_syscall => "afs_syscall",
        Syscall::tuxcall => "tuxcall",
        Syscall::security => "security",
        Syscall::gettid => "gettid",
        Syscall::readahead => "readahead",
        Syscall::setxattr => "setxattr",
        Syscall::lsetxattr => "lsetxattr",
        Syscall::fsetxattr => "fsetxattr",
        Syscall::getxattr => "getxattr",
        Syscall::lgetxattr => "lgetxattr",
        Syscall::fgetxattr => "fgetxattr",
        Syscall::listxattr => "listxattr",
        Syscall::llistxattr => "llistxattr",
        Syscall::flistxattr => "flistxattr",
        Syscall::removexattr => "removexattr",
        Syscall::lremovexattr => "lremovexattr",
        Syscall::fremovexattr => "fremovexattr",
        Syscall::tkill => "tkill",
        Syscall::time => "time",
        Syscall::futex => "futex",
        Syscall::sched_setaffinity => "sched_setaffinity",
        Syscall::sched_getaffinity => "sched_getaffinity",
        Syscall::set_thread_area => "set_thread_area",
        Syscall::io_setup => "io_setup",
        Syscall::io_destroy => "io_destroy",
        Syscall::io_getevents => "io_getevents",
        Syscall::io_submit => "io_submit",
        Syscall::io_cancel => "io_cancel",
        Syscall::get_thread_area => "get_thread_area",
        Syscall::lookup_dcookie => "lookup_dcookie",
        Syscall::epoll_create => "epoll_create",
        Syscall::epoll_ctl_old => "epoll_ctl_old",
        Syscall::epoll_wait_old => "epoll_wait_old",
        Syscall::remap_file_pages => "remap_file_pages",
        Syscall::getdents64 => "getdents64",
        Syscall::set_tid_address => "set_tid_address",
        Syscall::restart_syscall => "restart_syscall",
        Syscall::semtimedop => "semtimedop",
        Syscall::fadvise64 => "fadvise64",
        Syscall::timer_create => "timer_create",
        Syscall::timer_settime => "timer_settime",
        Syscall::timer_gettime => "timer_gettime",
        Syscall::timer_getoverrun => "timer_getoverrun",
        Syscall::timer_delete => "timer_delete",
        Syscall::clock_settime => "clock_settime",
        Syscall::clock_gettime => "clock_gettime",
        Syscall::clock_getres => "clock_getres",
        Syscall::clock_nanosleep => "clock_nanosleep",
        Syscall::exit_group => "exit_group",
        Syscall::epoll_wait => "epoll_wait",
        Syscall::epoll_ctl => "epoll_ctl",
        Syscall::tgkill => "tgkill",
        Syscall::utimes => "utimes",
        Syscall::vserver => "vserver",
        Syscall::mbind => "mbind",
        Syscall::set_mempolicy => "set_mempolicy",
        Syscall::get_mempolicy => "get_mempolicy",
        Syscall::mq_open => "mq_open",
        Syscall::mq_unlink => "mq_unlink",
        Syscall::mq_timedsend => "mq_timedsend",
        Syscall::mq_timedreceive => "mq_timedreceive",
        Syscall::mq_notify => "mq_notify",
        Syscall::mq_getsetattr => "mq_getsetattr",
        Syscall::kexec_load => "kexec_load",
        Syscall::waitid => "waitid",
        Syscall::add_key => "add_key",
        Syscall::request_key => "request_key",
        Syscall::keyctl => "keyctl",
        Syscall::ioprio_set => "ioprio_set",
        Syscall::ioprio_get => "ioprio_get",
        Syscall::inotify_init => "inotify_init",
        Syscall::inotify_add_watch => "inotify_add_watch",
        Syscall::inotify_rm_watch => "inotify_rm_watch",
        Syscall::migrate_pages => "migrate_pages",
        Syscall::openat => "openat",
        Syscall::mkdirat => "mkdirat",
        Syscall::mknodat => "mknodat",
        Syscall::fchownat => "fchownat",
        Syscall::futimesat => "futimesat",
        Syscall::newfstatat => "newfstatat",
        Syscall::unlinkat => "unlinkat",
        Syscall::renameat => "renameat",
        Syscall::linkat => "linkat",
        Syscall::symlinkat => "symlinkat",
        Syscall::readlinkat => "readlinkat",
        Syscall::fchmodat => "fchmodat",
        Syscall::faccessat => "faccessat",
        Syscall::pselect6 => "pselect6",
        Syscall::ppoll => "ppoll",
        Syscall::unshare => "unshare",
        Syscall::set_robust_list => "set_robust_list",
        Syscall::get_robust_list => "get_robust_list",
        Syscall::splice => "splice",
        Syscall::tee => "tee",
        Syscall::sync_file_range => "sync_file_range",
        Syscall::vmsplice => "vmsplice",
        Syscall::move_pages => "move_pages",
        Syscall::utimensat => "utimensat",
        Syscall::epoll_pwait => "epoll_pwait",
        Syscall::signalfd => "signalfd",
        Syscall::timerfd_create => "timerfd_create",
        Syscall::eventfd => "eventfd",
        Syscall::fallocate => "fallocate",
        Syscall::timerfd_settime => "timerfd_settime",
        Syscall::timerfd_gettime => "timerfd_gettime",
        Syscall::accept4 => "accept4",
        Syscall::signalfd4 => "signalfd4",
        Syscall::eventfd2 => "eventfd2",
        Syscall::epoll_create1 => "epoll_create1",
        Syscall::dup3 => "dup3",
        Syscall::pipe2 => "pipe2",
        Syscall::inotify_init1 => "inotify_init1",
        Syscall::preadv => "preadv",
        Syscall::pwritev => "pwritev",
        Syscall::rt_tgsigqueueinfo => "rt_tgsigqueueinfo",
        Syscall::perf_event_open => "perf_event_open",
        Syscall::recvmmsg => "recvmmsg",
        Syscall::fanotify_init => "fanotify_init",
        Syscall::fanotify_mark => "fanotify_mark",
        Syscall::prlimit64 => "prlimit64",
        Syscall::name_to_handle_at => "name_to_handle_at",
        Syscall::open_by_handle_at => "open_by_handle_at",
        Syscall::clock_adjtime => "clock_adjtime",
        Syscall::syncfs => "syncfs",
        Syscall::sendmmsg => "sendmmsg",
        Syscall::setns => "setns",
        Syscall::getcpu => "getcpu",
        Syscall::process_vm_readv => "process_vm_readv",
        Syscall::process_vm_writev => "process_vm_writev",
        Syscall::kcmp => "kcmp",
        Syscall::finit_module => "finit_module",
        Syscall::sched_setattr => "sched_setattr",
        Syscall::sched_getattr => "sched_getattr",
        Syscall::renameat2 => "renameat2",
        Syscall::seccomp => "seccomp",
        Syscall::getrandom => "getrandom",
        Syscall::memfd_create => "memfd_create",
        Syscall::kexec_file_load => "kexec_file_load",
        Syscall::bpf => "bpf",
        Syscall::execveat => "execveat",
        Syscall::userfaultfd => "userfaultfd",
        Syscall::membarrier => "membarrier",
        Syscall::mlock2 => "mlock2",
        Syscall::copy_file_range => "copy_file_range",
        Syscall::preadv2 => "preadv2",
        Syscall::pwritev2 => "pwritev2",
        Syscall::xstat => "xstat",
    }
}

fn syscall_to_num(s: Syscall) -> usize {
    unsafe {
        seccomp_syscall_resolve_name(std::ffi::CString::new(syscall_name(s))
                                     .unwrap().as_ptr()) as usize
    }
}

impl Rule {
	/// Create new rule for `syscall_nr` using comparison `cmp`.
	pub fn new(syscall_nr: usize, cmp: Cmp, action: Action) -> Rule {
		Rule {
			action: action,
			syscall_nr: syscall_nr,
			comparators: vec![cmp]
		}
	}
	/// Create new rule for `syscall` that gives an EPERM error.
	pub fn eperm(syscall: Syscall) -> Rule {
		Rule {
			action: Action::Errno(libc::EPERM),
			syscall_nr: syscall_to_num(syscall),
			comparators: Vec::new(),
		}
	}
	/// Create new rule for `syscall` that gives triggers ptrace.
	pub fn trace(syscall: Syscall, message: u32) -> Rule {
		Rule {
			action: Action::Trace(message),
			syscall_nr: syscall_to_num(syscall),
			comparators: Vec::new(),
		}
	}

	/// Adds comparison. Multiple comparisons will be
	/// ANDed together.
	pub fn add_comparison(&mut self, cmp: Cmp) {
		self.comparators.push(cmp);
	}
}

/// Error type
#[derive(Debug)]
pub struct SeccompError {
	msg: String
}

impl SeccompError {
	fn new<T: Into<String>>(msg: T) -> Self {
		SeccompError {
			msg: msg.into()
		}
	}
}

impl fmt::Display for SeccompError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			write!(f, "SeccompError: {}", self.msg)
	}
}

impl Error for SeccompError {
	fn description(&self) -> &str {
		&self.msg
	}
}

/// Seccomp context
#[derive(Debug)]
pub struct Context {
	int: *mut scmp_filter_ctx,
}

impl Context {
	/// Creates new context with default action
	pub fn default(def_action: Action) -> Result<Context,SeccompError> {
		let filter_ctx = unsafe { seccomp_init(def_action.into()) };
		if filter_ctx.is_null() {
			return Err(SeccompError::new("initialization failed"));
		}
		Ok(Context { int: filter_ctx })
	}

	/// Adds rule to the context
	pub fn add_rule(&mut self, rule: Rule) -> Result<(),SeccompError> {
		let res = unsafe {
			 seccomp_rule_add_array(self.int, rule.action.into(),
				 rule.syscall_nr as i32, rule.comparators.len() as u32,
				 rule.comparators.as_slice().as_ptr())
		};
		if res != 0 {
			Err(SeccompError::new(format!("failed to add rule {:?}", rule)))
		} else {
			Ok(())
		}
	}

  /// Adds an arch to the rule.
  pub fn add_arch(&mut self, arch: Arch) -> Result<(),SeccompError> {
      let res = unsafe { seccomp_arch_add(self.int, arch.0) };
      if res != 0 {
	      Err(SeccompError::new(format!("failed to add arch {:?}", arch)))
      } else {
          Ok(())
      }
  }

	/// Loads the filter into the kernel. Rules will be applied when this function returns.
	pub fn load(&self) -> Result<(),SeccompError> {
		let res = unsafe { seccomp_load(self.int) };
		if res != 0 {
			Err(SeccompError::new("failed to load filter into the kernel"))
		} else {
			Ok(())
		}
	}
}

impl Drop for Context {
	fn drop(&mut self) {
		unsafe { seccomp_release(self.int) }
	}
}

#[test]
fn setuid_is_105() {
    assert_eq!(105, syscall_to_num(Syscall::setuid));
}

#[test]
fn it_works() {
	  fn test() -> Result<(),Box<Error>> {
        let myuid = unsafe { libc::getuid() };

        // First check that setting our uid to ourselves does not
        // fail (without seccomp).
		    let ret = unsafe { libc::setuid(myuid) };
        println!("try 1: ret = {}, uid = {} (from {})", ret, unsafe { libc::getuid() },
                 myuid);
        assert_eq!(ret, 0);

		    // let mut ctx = try!(Context::default(Action::Allow));
		    // try!(ctx.add_rule(Rule::new(105, Compare::arg(0).using(Op::Eq).with(myuid as u64).build().unwrap(), Action::Errno(libc::EPERM))));
		    // try!(ctx.load());

		    // let ret = unsafe { libc::setuid(myuid) };
        // println!("ret = {}, uid = {} (from {})", ret, unsafe { libc::getuid() },
        //          myuid);
        // assert!(ret != 0);
		    Ok(())
	  }
	  test().unwrap();
}

#[test]
fn macro_works() {
	  fn test() -> Result<(),Box<Error>> {
        // first check that we can write 0 bytes before using seccomp
        // to restrict ourselves.
		    let ret = unsafe { libc::write(1,std::ptr::null(),0) };
        println!("ret is {} without seccomp", ret);
        assert_eq!(ret, 0);

		    let mut ctx = try!(Context::default(Action::Allow));
		    try!(ctx.add_rule(Rule::new(syscall_to_num(Syscall::write),
                                    scmp_cmp!( Arg(0) == 1 ),
                                    Action::Errno(libc::EPERM))));
		    try!(ctx.add_rule(Rule::new(syscall_to_num(Syscall::writev),
                                    scmp_cmp!( Arg(0) == 1 ),
                                    Action::Errno(libc::EPERM))));
		    try!(ctx.add_rule(Rule::new(syscall_to_num(Syscall::pwritev),
                                    scmp_cmp!( Arg(0) == 1 ),
                                    Action::Errno(libc::EPERM))));
		    try!(ctx.load());

		    let ret = unsafe { libc::write(1,std::ptr::null(),0) };
        println!("ret is {} with seccomp", ret);
        assert_eq!(ret, -1);
		    Ok(())
	  }
	  test().unwrap();
}

#[test]
fn eperm_works() {
	  fn test() -> Result<(),Box<Error>> {
        let myuid = unsafe { libc::getuid() };

		    let mut ctx = try!(Context::default(Action::Allow));
		    try!(ctx.add_rule(Rule::eperm(Syscall::getuid)));
		    try!(ctx.load());

		    let ret = unsafe { libc::getuid() };
        println!("ret = {} (from {}) vs {}", ret, myuid, 0xffffffff as usize);
        assert!(ret == 0xffffffff);
		    Ok(())
	  }
	  test().unwrap();
}
