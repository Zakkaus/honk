//! The TUN descriptor the Endpoint reads and writes. The daemon opens its own
//! device by name ([`TunDevice::open`]) and configures the link in `setup`; an
//! embedder hands over one it opened ([`TunDevice::adopt`]).

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt as _;

use anyhow::ensure;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

use super::Framing;

pub(super) const OFFLOADS: libc::c_ulong =
    (libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6) as libc::c_ulong;

/// The only descriptor of the daemon's TUN device; the non-persistent link
/// exists exactly while it stays open. Never cloned or duplicated.
pub(crate) struct TunDevice {
    pub(super) fd: OwnedFd,
    pub(super) ifindex: u32,
    pub(super) incarnation: u64,
    framing: Framing,
}

impl AsFd for TunDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// `attached`: `TUNSETIFF` had attached a device, which the dropped
/// descriptor then released.
pub(super) struct OpenError {
    pub(super) attached: bool,
    pub(super) error: io::Error,
}

impl TunDevice {
    pub(super) fn open(name: &str, incarnation: u64) -> Result<Self, OpenError> {
        let refused = |error: io::Error| OpenError {
            attached: false,
            error,
        };
        let mut request = interface_request(name).map_err(refused)?;
        let fd = open(
            "/dev/net/tun",
            OFlag::O_RDWR | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| refused(errno.into()))?;
        // The ioctl takes a C short; IFF_TUN_EXCL is its sign bit.
        request.ifr_ifru.ifru_flags =
            (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR | libc::IFF_TUN_EXCL)
                as libc::c_short;
        // SAFETY: TUNSETIFF reads and updates only this live, initialized ifreq.
        if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
            return Err(refused(io::Error::last_os_error()));
        }
        Self::attached(fd, name, incarnation).map_err(|error| OpenError {
            attached: true,
            error,
        })
    }

    fn attached(fd: OwnedFd, name: &str, incarnation: u64) -> io::Result<Self> {
        verify_attachment(&fd, name)?;
        configure_vnet(fd.as_raw_fd())?;
        same_namespace(&fd)?;
        let ifindex = nix::net::if_::if_nametoindex(name)?;
        Ok(Self {
            fd,
            ifindex,
            incarnation,
            framing: Framing::Vnet,
        })
    }

    /// Take a descriptor an embedder opened and configured itself (Android
    /// `VpnService`): a single-queue `IFF_TUN | IFF_NO_PI` device without
    /// `IFF_VNET_HDR`, so its records are bare IP packets. Its link belongs to
    /// the embedder; only `O_NONBLOCK` is set on the descriptor.
    pub(crate) fn adopt(fd: OwnedFd) -> io::Result<Self> {
        let flags = attachment(&fd)?.1;
        if !valid_adopted_flags(flags) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "adopted TUN is not a single-queue IFF_TUN|IFF_NO_PI device (flags {flags:#x})"
                ),
            ));
        }
        let status = nix::fcntl::fcntl(&fd, nix::fcntl::FcntlArg::F_GETFL)?;
        nix::fcntl::fcntl(
            &fd,
            nix::fcntl::FcntlArg::F_SETFL(OFlag::from_bits_retain(status) | OFlag::O_NONBLOCK),
        )?;
        Ok(Self {
            fd,
            ifindex: 0,
            incarnation: 0,
            framing: Framing::Plain,
        })
    }

    pub(crate) fn framing(&self) -> Framing {
        self.framing
    }

    pub(crate) fn new_auxiliary(name: &str) -> io::Result<Self> {
        Self::open(name, 0).map_err(|failure| failure.error)
    }

    pub(crate) fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub(crate) fn verify_auxiliary(&self, name: &str) -> anyhow::Result<()> {
        same_namespace(&self.fd)?;
        verify_attachment(&self.fd, name)?;
        ensure!(
            nix::net::if_::if_nametoindex(name)? == self.ifindex,
            "private TUN ifindex changed"
        );
        Ok(())
    }
}

fn valid_attachment_flags(flags: libc::c_int) -> bool {
    flags & !libc::IFF_TUN_EXCL == libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR
}

/// The embedder owns the link's lifetime and exclusivity, so persistence and
/// `IFF_TUN_EXCL` are its choice.
fn valid_adopted_flags(flags: libc::c_int) -> bool {
    flags & !(libc::IFF_TUN_EXCL | libc::IFF_PERSIST) == libc::IFF_TUN | libc::IFF_NO_PI
}

fn configure_vnet(fd: RawFd) -> io::Result<()> {
    for (set, get, expected, contract) in [
        (
            libc::TUNSETVNETHDRSZ,
            libc::TUNGETVNETHDRSZ,
            super::VNET_BYTES as libc::c_int,
            "10-byte vnet header",
        ),
        (
            libc::TUNSETVNETLE,
            libc::TUNGETVNETLE,
            1,
            "little-endian vnet header",
        ),
    ] {
        let value = expected;
        // SAFETY: each SET reads one initialized int and fd stays owned by the caller.
        if unsafe { libc::ioctl(fd, set, &value) } < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("TUN requires {contract}: {}", io::Error::last_os_error()),
            ));
        }
        let mut actual: libc::c_int = -1;
        // SAFETY: each GET writes one int while fd remains owned by the caller.
        if unsafe { libc::ioctl(fd, get, &mut actual) } < 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "TUN requires {contract} readback: {}",
                    io::Error::last_os_error()
                ),
            ));
        }
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TUN {contract} readback is {actual}, expected {expected}"),
            ));
        }
    }
    // SAFETY: TUNSETOFFLOAD takes its offload mask by value.
    if unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD, OFFLOADS) } < 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "TUN requires checksum and TCPv4/TCPv6 segmentation: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

/// The attached device's request (for its name) and flags, from `TUNGETIFF`.
fn attachment(fd: &OwnedFd) -> io::Result<(libc::ifreq, libc::c_int)> {
    // SAFETY: zero initializes every byte returned by TUNGETIFF.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: the kernel writes only the initialized ifreq while fd stays owned.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETIFF, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: TUNGETIFF initializes this union member.
    let flags = libc::c_int::from(unsafe { request.ifr_ifru.ifru_flags } as u16);
    Ok((request, flags))
}

pub(super) fn verify_attachment(fd: &OwnedFd, name: &str) -> io::Result<()> {
    let (request, flags) = attachment(fd)?;
    let actual = request
        .ifr_name
        .iter()
        .map(|&byte| byte as u8)
        .take_while(|&byte| byte != 0);
    if !actual.eq(name.bytes()) || !valid_attachment_flags(flags) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "TUN attachment is not a single-queue IFF_TUN|IFF_NO_PI|IFF_VNET_HDR {name} (flags {flags:#x})"
            ),
        ));
    }
    Ok(())
}

fn interface_request(name: &str) -> io::Result<libc::ifreq> {
    // SAFETY: an all-zero ifreq is the empty C value.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    if name.is_empty() || name.len() >= request.ifr_name.len() || name.bytes().any(|byte| byte == 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN name must be 1 to 15 bytes without NUL",
        ));
    }
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    Ok(request)
}

/// The receipt is named by this thread's namespace cookie, so the device must
/// live in the same namespace.
pub(super) fn same_namespace(device: &OwnedFd) -> io::Result<()> {
    // SAFETY: TUNGETDEVNETNS takes no argument and returns a new descriptor or -1.
    let raw = unsafe { libc::ioctl(device.as_raw_fd(), libc::TUNGETDEVNETNS) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just installed this descriptor and nothing else owns it.
    let namespace = File::from(unsafe { OwnedFd::from_raw_fd(raw) }).metadata()?;
    let current = std::fs::metadata("/proc/thread-self/ns/net")?;
    if (namespace.dev(), namespace.ino()) != (current.dev(), current.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TUN device is outside the daemon's network namespace",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
