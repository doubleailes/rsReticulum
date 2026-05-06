#[path = "../commands/rnstatus.rs"]
mod rnstatus;

fn main() -> std::process::ExitCode {
    rnstatus::main()
}
