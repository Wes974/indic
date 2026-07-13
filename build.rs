fn main() {
    let css = std::fs::read_to_string("src/web/style.css").unwrap();
    let js = std::fs::read_to_string("src/web/app.js").unwrap();
    let html = std::fs::read_to_string("src/web/index.html").unwrap();

    // Replace external refs with inline content
    let html = html.replace(
        "<link rel=\"stylesheet\" href=\"style.css\">",
        &format!("<style>{}</style>", css),
    );
    let html = html.replace(
        "<script src=\"app.js\"></script>",
        &format!("<script>{}</script>", js),
    );

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out_dir}/index.html"), html).unwrap();

    // Re-run if source files change
    println!("cargo:rerun-if-changed=src/web/index.html");
    println!("cargo:rerun-if-changed=src/web/style.css");
    println!("cargo:rerun-if-changed=src/web/app.js");
}
