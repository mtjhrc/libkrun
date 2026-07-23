#[allow(dead_code)]
mod builder;

#[cfg(feature = "aws-nitro")]
use std::path::PathBuf;
#[cfg(feature = "aws-nitro")]
use std::sync::Mutex;

#[cfg(feature = "aws-nitro")]
static KRUN_NITRO_DEBUG: Mutex<bool> = Mutex::new(false);

/// AWS Nitro enclave-specific configuration.
///
/// These fields are only used by the aws-nitro path, which delivers
/// exec_path/argv/envp over vsock to the enclave initramfs.
#[cfg(feature = "aws-nitro")]
#[derive(Default)]
struct NitroConfig {
    workdir: Option<String>,
    exec_path: Option<String>,
    env: Option<String>,
    args: Option<String>,
    rlimits: Option<String>,
    console_output: Option<PathBuf>,
}

#[cfg(feature = "aws-nitro")]
impl NitroConfig {
    fn set_workdir(&mut self, workdir: String) {
        self.workdir = Some(workdir);
    }

    fn set_exec_path(&mut self, exec_path: String) {
        self.exec_path = Some(exec_path);
    }

    fn set_env(&mut self, env: String) {
        self.env = Some(env);
    }

    fn set_args(&mut self, args: String) {
        self.args = Some(args);
    }

    fn set_rlimits(&mut self, rlimits: String) {
        self.rlimits = Some(rlimits);
    }
}
