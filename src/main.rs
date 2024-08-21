use std::fs::File;
use std::io::{self, Read};

fn main() -> io::Result<()> {
    let mut file = File::open("test")?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    match tamanegi::parse_findings(&contents) {
        Ok((_, findings)) => {
            for finding in findings {
                println!("{:#?}", finding);
            }
        }
        Err(e) => {
            eprintln!("Failed to parse input: {:?}", e);
        }
    }

    Ok(())
}
