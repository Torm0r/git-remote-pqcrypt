use std::env;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::os::unix::io::{AsRawFd, FromRawFd}; // Import FromRawFd trait
use std::thread;

fn main() {
    let args: Vec<String> = env::args().collect();
    eprintln!(
        "[DEBUG] git-remote-debug invoked with arguments: {:?}",
        args
    );

    // Open /dev/tty for user input
    let tty_input = File::options()
        .read(true)
        .open("/dev/tty")
        .expect("Failed to open /dev/tty. This tool requires a Unix-like terminal environment.");

    let tty_fd = tty_input.as_raw_fd();
    let tty_reader = unsafe {
        // SAFETY: We are creating a new File from an existing file descriptor.
        // The original tty_input is moved into the thread, so there's no double close.
        File::from_raw_fd(tty_fd)
    };

    let git_to_terminal_handle = thread::spawn(move || {
        let stdin = io::stdin();
        let mut stdin_lock = stdin.lock();
        let mut line = String::new();

        loop {
            line.clear();
            match stdin_lock.read_line(&mut line) {
                Ok(0) => {
                    // EOF reached, Git closed the connection
                    eprintln!("[DEBUG] Git stdin EOF. Exiting thread A.");
                    break;
                }
                Ok(_) => {
                    eprint!("[GIT]  <- {}", line);
                    io::stderr().flush().expect("Failed to flush stderr");
                }
                Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => {
                    // Git pipe disconnected, exit cleanly
                    eprintln!("[DEBUG] Git stdin broken pipe. Exiting thread A.");
                    break;
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to read from stdin: {}", e);
                    break;
                }
            }
        }
    });

    let terminal_to_git_handle = thread::spawn(move || {
        let mut stdout = io::stdout();
        let mut tty_reader_buf = io::BufReader::new(tty_reader);
        let mut line = String::new();

        loop {
            line.clear();
            match tty_reader_buf.read_line(&mut line) {
                Ok(0) => {
                    // EOF from TTY (Ctrl+D), user wants to terminate
                    eprintln!("[DEBUG] TTY EOF. Exiting thread B.");
                    break;
                }
                Ok(_) => {
                    eprint!("[USER] -> {}", line);
                    io::stderr().flush().expect("Failed to flush stderr");
                    match stdout.write_all(line.as_bytes()) {
                        Ok(_) => {
                            stdout.flush().expect("Failed to flush stdout to Git");
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::BrokenPipe => {
                            // Git pipe disconnected, exit cleanly
                            eprintln!("[DEBUG] Git stdout broken pipe. Exiting thread B.");
                            break;
                        }
                        Err(e) => {
                            eprintln!("[ERROR] Failed to write to stdout: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to read from /dev/tty: {}", e);
                    break;
                }
            }
        }
    });

    git_to_terminal_handle.join().expect("Thread A panicked");
    terminal_to_git_handle.join().expect("Thread B panicked");

    eprintln!("[DEBUG] git-remote-debug exiting cleanly.");
}
