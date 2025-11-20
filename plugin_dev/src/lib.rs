use serde::{ Deserialize, Serialize };

#[derive(Deserialize)]
struct Input {
    target: String,
}

#[derive(Serialize)]
struct Finding {
    name: String,
    severity: String,
    description: String,
    evidence: String,
}

#[no_mangle]
pub extern "C" fn analyze() {}
