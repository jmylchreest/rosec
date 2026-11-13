//! A disposable bus for fixtures that claim production service names.
pub struct PrivateBus {
    child: std::process::Child,
    pub address: String,
}
impl PrivateBus {
    pub fn new() -> Self {
        use std::io::BufRead;
        let child = std::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start private test bus (requires dbus-daemon)");
        let mut bus = Self {
            child,
            address: String::new(),
        };
        std::io::BufReader::new(bus.child.stdout.take().unwrap())
            .read_line(&mut bus.address)
            .expect("read private test bus address");
        bus.address = bus.address.trim().to_owned();
        assert!(
            !bus.address.is_empty(),
            "private test bus returned no address"
        );
        bus
    }
}
impl Drop for PrivateBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
