# Rust Web Fuzz (RWF)

RWF è uno scanner di vulnerabilità web ad alte prestazioni, modulare ed estensibile, scritto interamente in Rust. Supporta plugin dinamici via WebAssembly e motori di fuzzing personalizzabili.

## ⚠️ Disclaimer Legale

**QUESTO SOFTWARE È SOLO A SCOPO DI TESTING DIFENSIVO.**
L'autore non si assume alcuna responsabilità per l'uso improprio di questo strumento. Utilizzare RWF solo su sistemi di tua proprietà o su sistemi per i quali hai un'autorizzazione scritta esplicita.

## Caratteristiche
* ⚡ **Veloce**: Scritto in Rust con runtime asincrono Tokio.
* 🧩 **Modulare**: Plugin system basato su WASM (Hot-reloading).
* 🛡️ **Safe**: Rilevamento vulnerabilità non distruttivo.
* 📊 **Reportistica**: Output JSON e HTML.

## Installazione

### Prerequisiti
* Rust 1.70+ (`rustup`)
* Target WASM (opzionale per dev plugin): `rustup target add wasm32-wasi`

### Build
```bash
git clone [https://github.com/Gabryx412-Coder/rust-web-fuzz](https://github.com/Gabryx412-Coder/rust-web-fuzz)
cd rust-web-fuzz
make setup
cargo build --release
