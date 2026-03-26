use krun::{
    BalloonDevice, ConsoleDevice, ConsoleDeviceBuilder, FsDevice, KrunLog, KrunVmm, LibkrunInit,
    LibkrunInitBuilder, RngDevice, VmmBuilder,
};

krun::error_code_error_ffier!("krun");

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

fn main() {
    let header = ffier::HeaderBuilder::new("LIBKRUN_H")
        .add(krun_error_code__header())
        .add(krun_krunlog__header())
        .add(krun_fsdevice__header())
        .add(krun_consoledevice__header())
        .add(krun_consoledevicebuilder__header())
        .add(krun_balloondevice__header())
        .add(krun_rngdevice__header())
        .add(krun_libkruninit__header())
        .add(krun_libkruninitbuilder__header())
        .add(krun_vmmbuilder__header())
        .add(krun_krunvmm__header())
        .build();
    print!("{header}");
}
