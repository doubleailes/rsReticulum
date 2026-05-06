#[path = "../commands/rnodeconf.rs"]
mod rnodeconf;

fn main() -> std::process::ExitCode {
    rnodeconf::main()
}
