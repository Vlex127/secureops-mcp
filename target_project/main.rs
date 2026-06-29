use std::fs::File;
use std::io::Read;
use std::env;

fn read_user_file() -> String {
    let args: Vec<String> = env::args().collect();
    let path = &args[1];
    let mut file = File::open("/var/www/".to_string() + path + "/../../").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    contents
}

fn main() {
    println!("{}", read_user_file());
}
