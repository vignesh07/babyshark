use anyhow::Result;
use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
#[command(name = "babyshark", about = "Flows-first PCAP TUI (WIP)")]
#[command(group(
    ArgGroup::new("input")
        .required(true)
        .args(["pcap", "live", "list_ifaces"]),
))]
struct Args {
    /// Path to a .pcap or .pcapng file
    #[arg(long)]
    pcap: Option<String>,

    /// Capture packets from a live interface via tshark (e.g. en0)
    #[arg(long)]
    live: Option<String>,

    /// List capture interfaces via tshark
    #[arg(long)]
    list_ifaces: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_ifaces {
        let ver = babyshark::live::tshark_version().map_err(|e| {
            anyhow::anyhow!("tshark not available (required for --list-ifaces): {e}")
        })?;
        println!("{ver}");

        let ifaces = babyshark::live::tshark_list_ifaces()?;
        if ifaces.is_empty() {
            println!("(no interfaces found)");
        } else {
            for i in ifaces {
                if let Some(desc) = i.desc {
                    println!("{}. {} ({})", i.index, i.name, desc);
                } else {
                    println!("{}. {}", i.index, i.name);
                }
            }
        }
        return Ok(());
    }

    if let Some(pcap) = args.pcap {
        let rows = babyshark::pcap::read_pcap(&pcap)?;
        let flows = babyshark::flow::FlowIndex::build(&rows);
        let mut app = babyshark::ui::App::new(&pcap, rows, flows);
        babyshark::ui::run_tui(&mut app)?;
        return Ok(());
    }

    if let Some(_iface) = args.live {
        return Err(anyhow::anyhow!(
            "live capture is not implemented yet; use --list-ifaces to discover interfaces"
        ));
    }

    // clap should prevent this
    Err(anyhow::anyhow!(
        "must specify one of --pcap, --live, or --list-ifaces"
    ))
}
