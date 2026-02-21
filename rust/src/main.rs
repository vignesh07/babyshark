use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "babyshark", about = "Flows-first PCAP TUI (WIP)")]
struct Args {
    /// Path to a .pcap or .pcapng file
    #[arg(long)]
    pcap: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let rows = babyshark::pcap::read_pcap(&args.pcap)?;
    let flows = babyshark::flow::FlowIndex::build(&rows);
    let mut app = babyshark::ui::App::new(rows, flows);

    babyshark::ui::run_tui(&mut app)?;
    Ok(())
}
