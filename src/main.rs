use anyhow::Result;
use clap::Parser;
use firewall::firewall;

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    debug: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = firewall::Config { debug: cli.debug, ..Default::default() };
    let mut component = firewall::new(config);
    
    component.initialize()?;
    component.start()?;
    
    println!("SigmaOS-firewall running (Ctrl+C to stop)");
    tokio::runtime::Runtime::new()?.block_on(async {
        tokio::signal::ctrl_c().await.unwrap();
    });
    
    component.stop()?;
    Ok(())
}
