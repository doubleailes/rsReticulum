#[path = "../commands/rnsh.rs"]
mod rnsh;

fn main() -> std::process::ExitCode {
    rnsh::main()
}
