extern crate seccomp_sys;
extern crate libc;

use seccomp_sys::*;
pub use seccomp_sys::scmp_compare::*;

#[derive(Debug)]
pub enum Action {
	Allow,
	Kill,
	Trap
}

impl Action {
	fn to_c(&self) -> libc::uint32_t {
		match *self {
			Action::Allow => SCMP_ACT_ALLOW,
			Action::Kill => SCMP_ACT_KILL,
			Action::Trap => SCMP_ACT_TRAP,
		}
	}
}

pub struct Compare {
	arg: libc::c_uint,
	op: Option<scmp_compare>,
	datum_a: Option<scmp_datum_t>,
	datum_b: Option<scmp_datum_t>,
}

impl Compare {
	pub fn arg(arg_num: u32) -> Self {
		Compare { arg: arg_num as libc::c_uint, op: None, datum_a: None, datum_b: None }
	}

	pub fn using(mut self, op: scmp_compare) -> Self {
		self.op = Some(op);
		self
	}

	pub fn with(mut self, datum: u64) -> Self {
		self.datum_a = Some(datum);
		self
	}


	pub fn and(mut self, datum: u64) -> Self {
		self.datum_b = Some(datum);
		self
	}

	pub fn build(self) -> Option<scmp_arg_cmp> {
		if self.op.is_some() && self.datum_a.is_some() {
			Some(scmp_arg_cmp { arg: self.arg, op: self.op.unwrap(), datum_a: self.datum_a.unwrap(), datum_b: self.datum_b.unwrap_or(0) })
		} else {
			None
		}
	}
}

pub struct Rule {
	action: Action,
	syscall_nr: usize,
	comparators: Vec<scmp_arg_cmp>,
}

impl Rule {
	pub fn new(syscall_nr: usize, cmp: scmp_arg_cmp, action: Action) -> Rule {
		Rule {
			action: action,
			syscall_nr: syscall_nr,
			comparators: vec![cmp]
		}
	}
}

#[derive(Debug)]
pub struct Context {
	int: *mut scmp_filter_ctx,
}

impl Context {
	pub fn default(def_action: Action) -> Context {
		Context { int: unsafe { seccomp_init(def_action.to_c()) } }
	}

	pub fn add_rule(&mut self, rule: Rule) {
		unsafe { seccomp_rule_add(self.int, rule.action.to_c(), rule.syscall_nr as i32, rule.comparators.len() as u32, rule.comparators); }
	}

	pub fn load(&self) {
		unsafe { seccomp_load(self.int) };
	}
}

impl Drop for Context {
	fn drop(&mut self) {
		unsafe { seccomp_release(self.int) }
	}
}

#[test]
fn it_works() {
	use std::fs::File;
	let mut ctx = Context::default(Action::Allow);
	ctx.add_rule(Rule::new(105, Compare::arg(0).using(SCMP_CMP_EQ).with(1000).build().unwrap(), Action::Kill));
	ctx.load();
	File::open("/etc/passwd");
}
