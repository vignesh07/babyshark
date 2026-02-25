use anyhow::Result;
use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
#[command(name = "babyshark", about = "Flows-first PCAP TUI (WIP)")]
#[command(group(
    ArgGroup::new("input")
        .required(false)
        .args(["pcap", "live", "list_ifaces"]),
))]
struct Args {
    /// Path to a .pcap or .pcapng file
    #[arg(long)]
    pcap: Option<String>,

    /// Capture packets from a live interface via tshark (e.g. en0)
    #[arg(long)]
    live: Option<String>,

    /// BPF capture filter passed to tshark (-f) in live mode (e.g. "tcp port 443")
    #[arg(long)]
    bpf: Option<String>,

    /// Wireshark display filter passed to tshark (-Y) in live mode (e.g. "tcp.port==443")
    #[arg(long)]
    dfilter: Option<String>,

    /// List capture interfaces via tshark
    #[arg(long)]
    list_ifaces: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // No-args interactive launcher.
    if !args.list_ifaces && args.pcap.is_none() && args.live.is_none() {
        return interactive_launcher();
    }

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

    if let Some(iface) = args.live {
        babyshark::live::tshark_live_preflight(&iface)?;
        let (rx, err_rx, stop_tx) = babyshark::live::spawn_live_capture_tshark_fields(
            iface.clone(),
            args.bpf.clone(),
            args.dfilter.clone(),
        )?;
        let mut app = babyshark::ui::App::new(
            &format!("live:{iface}"),
            Vec::new(),
            babyshark::flow::FlowIndex::default(),
        );
        app.live_iface = Some(iface);
        app.live_rx = Some(rx);
        app.live_err_rx = Some(err_rx);
        app.live_stop_tx = Some(stop_tx);
        babyshark::ui::run_tui(&mut app)?;
        return Ok(());
    }

    // If we got here, args were incomplete.
    Err(anyhow::anyhow!(
        "must specify one of --pcap, --live, or --list-ifaces"
    ))
}

fn interactive_launcher() -> Result<()> {
    use std::io::{stdin, stdout, Write};

    println!("babyshark (interactive)\n");
    println!("Choose an input:");
    println!("  1) Live capture (pick an interface)");
    println!("  2) Open a PCAP file (.pcap/.pcapng)");
    println!("  q) Quit");

    print!("\n> ");
    let _ = stdout().flush();

    let mut choice = String::new();
    stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    match choice {
        "1" => interactive_live_capture(),
        "2" => interactive_open_pcap(),
        "q" | "Q" => Ok(()),
        _ => {
            println!("(unknown choice)");
            Ok(())
        }
    }
}

fn interactive_open_pcap() -> Result<()> {
    use std::io::{stdin, stdout, Write};

    println!("\nEnter path to .pcap/.pcapng:");
    print!("> ");
    let _ = stdout().flush();

    let mut p = String::new();
    stdin().read_line(&mut p)?;
    let p = p.trim().to_string();
    if p.is_empty() {
        return Ok(());
    }

    let rows = babyshark::pcap::read_pcap(&p)?;
    let flows = babyshark::flow::FlowIndex::build(&rows);
    let mut app = babyshark::ui::App::new(&p, rows, flows);
    babyshark::ui::run_tui(&mut app)?;
    Ok(())
}

fn interactive_live_capture() -> Result<()> {
    use std::io::{stdin, stdout, Write};

    let ver = babyshark::live::tshark_version()
        .map_err(|e| anyhow::anyhow!("tshark not available (required for live capture): {e}"))?;
    println!("\n{ver}\n");

    let ifaces = babyshark::live::tshark_list_ifaces()?;
    if ifaces.is_empty() {
        println!("(no interfaces found)");
        return Ok(());
    }

    println!("Pick an interface:");
    for i in &ifaces {
        if let Some(desc) = &i.desc {
            println!("{}. {} ({})", i.index, i.name, desc);
        } else {
            println!("{}. {}", i.index, i.name);
        }
    }

    println!("\nEnter interface number (or q to quit):");
    print!("> ");
    let _ = stdout().flush();

    let mut s = String::new();
    stdin().read_line(&mut s)?;
    let s = s.trim();
    if s.eq_ignore_ascii_case("q") || s.is_empty() {
        return Ok(());
    }

    let idx: usize = s.parse().map_err(|_| anyhow::anyhow!("invalid number"))?;
    let iface = ifaces
        .iter()
        .find(|i| i.index == idx)
        .map(|i| i.name.clone())
        .ok_or_else(|| anyhow::anyhow!("unknown interface index {idx}"))?;

    babyshark::live::tshark_live_preflight(&iface)?;
    let (rx, err_rx, stop_tx) =
        babyshark::live::spawn_live_capture_tshark_fields(iface.clone(), None, None)?;

    let mut app = babyshark::ui::App::new(
        &format!("live:{iface}"),
        Vec::new(),
        babyshark::flow::FlowIndex::default(),
    );
    app.live_iface = Some(iface);
    app.live_rx = Some(rx);
    app.live_err_rx = Some(err_rx);
    app.live_stop_tx = Some(stop_tx);
    babyshark::ui::run_tui(&mut app)?;

    Ok(())
}
