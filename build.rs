//! Inline `style.css` et `app.js` dans `index.html` à la compilation : le
//! binaire sert ainsi toute l'app en une seule requête, sans asset à déployer.

/// Remplace `needle` par `replacement`, en échouant le build si la balise n'a
/// pas été trouvée. Sans ce garde-fou, reformater la balise dans `index.html`
/// (guillemets, espaces, ordre des attributs) produirait silencieusement une
/// page au `<link>`/`<script>` mort : build vert, page sans style ni JS.
fn inline(html: &str, needle: &str, replacement: String) -> String {
    let count = html.matches(needle).count();
    assert!(
        count == 1,
        "build.rs : balise attendue exactement 1 fois dans src/web/index.html, \
         trouvée {count} fois — {needle:?}\n\
         Si la balise a été reformatée, mettre à jour build.rs en conséquence."
    );
    html.replace(needle, &replacement)
}

fn main() {
    let css = std::fs::read_to_string("src/web/style.css").unwrap();
    let js = std::fs::read_to_string("src/web/app.js").unwrap();
    let html = std::fs::read_to_string("src/web/index.html").unwrap();

    // `</script>` dans une chaîne JS clôturerait la balise inline côté parseur
    // HTML et couperait l'app en deux au milieu du fichier.
    assert!(
        !js.contains("</script"),
        "build.rs : src/web/app.js contient « </script » — il fermerait la \
         balise <script> inline. L'échapper (ex. \"<\\/script\")."
    );

    let html = inline(
        &html,
        "<link rel=\"stylesheet\" href=\"style.css\">",
        format!("<style>{css}</style>"),
    );
    let html = inline(
        &html,
        "<script src=\"app.js\"></script>",
        format!("<script>{js}</script>"),
    );

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out_dir}/index.html"), html).unwrap();

    // Re-run if source files change
    println!("cargo:rerun-if-changed=src/web/index.html");
    println!("cargo:rerun-if-changed=src/web/style.css");
    println!("cargo:rerun-if-changed=src/web/app.js");
}
