use krun::{
    BalloonDevice, ConsoleDevice, ConsoleDeviceBuilder, FsDevice, KrunLog, KrunVmm, LibkrunInit,
    LibkrunInitBuilder, RngDevice, VmmBuilder,
};

// Generate error FFI helpers once (message/free functions for KrunErrorCode).
krun::error_code_error_ffier!("krun");

// Bridge macros for all exported types:
krun::vmmbuilder_ffier!(VmmBuilder<'static>);
krun::krunvmm_ffier!(KrunVmm<'static>);
krun::fsdevice_ffier!(FsDevice<'static>);
krun::consoledevice_ffier!(ConsoleDevice<'static>);
krun::consoledevicebuilder_ffier!(ConsoleDeviceBuilder<'static>);
krun::balloondevice_ffier!(BalloonDevice);
krun::rngdevice_ffier!(RngDevice);
krun::libkruninit_ffier!(LibkrunInit);
krun::libkruninitbuilder_ffier!(LibkrunInitBuilder);
krun::krunlog_ffier!(KrunLog);
