use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "babyshark", about = "Flows-first PCAP TUI (WIP)")]
struct Args {
    /// Path to a .pcap or .pcapng file
    #[arg(long)]
    pcap: Option<String>,
}

fn main() {
    let args = Args::parse();
    if args.pcap.is_none() {
        eprintln!("usage: babyshark --pcap <file>");
        std::process::exit(2);
    }

    println!(
        "babyshark: opening {} (pcap viewer coming next)",
        args.pcap.unwrap()
    );
}
